//! End-to-end regression for the VMess body AEAD nonce budget (issue #513).
//!
//! The body key and IV are derived once per connection and the record counter
//! occupies the first two nonce bytes, so a physical connection may seal at most
//! 65,536 records. Past that the u16 counter wraps and record 65,537 reuses
//! record 1's (key, nonce) — two seals under one AEAD pair leak the XOR of the
//! plaintexts and the authentication key with it. VMess negotiates no rekey, so
//! the connection has to be retired instead.
//!
//! This drives a real [`VmessAdapter`] against a mock server that decrypts every
//! body record under its own sequential counter and asserts the server sees
//! exactly 65,536 records before EOF: the budget is enforced, the wire nonce
//! format is untouched, and the physical connection is closed rather than
//! reused. Mux needs no separate case — it multiplexes logical streams over one
//! body cipher, so they all draw from this same counter and the session dies
//! with it.

use std::sync::Arc;
use std::time::Duration;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, KeyInit, Nonce};
use meow_common::{Metadata, ProxyAdapter};
use meow_proxy::dialer::DirectDialer;
use meow_proxy::vmess::header::cmd_key;
use meow_proxy::vmess::Security;
use meow_proxy::{TransportChain, VmessAdapter};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Records one AEAD key/nonce pair may carry — the range of the two-byte record
/// counter that forms the nonce prefix.
const MAX_RECORDS: usize = 65_536;

// ─── VMess AEAD KDF — verbatim port of crates/meow-proxy/src/vmess/kdf.rs ────

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn nested_hmac(keys: &[&[u8]], msg: &[u8]) -> [u8; 32] {
    let Some((k, inner_keys)) = keys.split_last() else {
        return sha256(msg);
    };
    let mut key_block = [0u8; 64];
    if k.len() > 64 {
        key_block[..32].copy_from_slice(&nested_hmac(inner_keys, k));
    } else {
        key_block[..k.len()].copy_from_slice(k);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }
    let mut inner_msg = Vec::with_capacity(64 + msg.len());
    inner_msg.extend_from_slice(&ipad);
    inner_msg.extend_from_slice(msg);
    let inner_digest = nested_hmac(inner_keys, &inner_msg);
    let mut outer_msg = Vec::with_capacity(64 + 32);
    outer_msg.extend_from_slice(&opad);
    outer_msg.extend_from_slice(&inner_digest);
    nested_hmac(inner_keys, &outer_msg)
}

fn kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    let mut keys: Vec<&[u8]> = Vec::with_capacity(1 + path.len());
    keys.push(b"VMess AEAD KDF");
    keys.extend_from_slice(path);
    nested_hmac(&keys, key)
}

fn kdf16(key: &[u8], path: &[&[u8]]) -> [u8; 16] {
    kdf(key, path)[..16].try_into().unwrap()
}

fn kdf12(key: &[u8], path: &[&[u8]]) -> [u8; 12] {
    kdf(key, path)[..12].try_into().unwrap()
}

// ─── Mock VMess server helpers ───────────────────────────────────────────────

/// The wire nonce: `count(2 BE) || iv[2..12]`.
fn record_nonce(iv: &[u8; 16], counter: u16) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..2].copy_from_slice(&counter.to_be_bytes());
    nonce[2..].copy_from_slice(&iv[2..12]);
    nonce
}

/// The response body key/iv: SHA-256 of the request key/iv, truncated to 16.
fn response_body_keys(req_key: &[u8; 16], req_iv: &[u8; 16]) -> ([u8; 16], [u8; 16]) {
    let k: [u8; 32] = Sha256::digest(req_key).into();
    let i: [u8; 32] = Sha256::digest(req_iv).into();
    (k[..16].try_into().unwrap(), i[..16].try_into().unwrap())
}

/// Seal the AEAD response header the relay's read side expects.
fn seal_response_header(req_key: &[u8; 16], req_iv: &[u8; 16], resp_v: u8) -> Vec<u8> {
    let (resp_key, resp_iv) = response_body_keys(req_key, req_iv);
    let header = [resp_v, 0, 0, 0];

    let len_key = kdf16(&resp_key, &[b"AEAD Resp Header Len Key"]);
    let len_iv = kdf12(&resp_iv, &[b"AEAD Resp Header Len IV"]);
    let len_ct = Aes128Gcm::new_from_slice(&len_key)
        .unwrap()
        .encrypt(
            Nonce::from_slice(&len_iv),
            (header.len() as u16).to_be_bytes().as_ref(),
        )
        .unwrap();

    let header_key = kdf16(&resp_key, &[b"AEAD Resp Header Key"]);
    let header_iv = kdf12(&resp_iv, &[b"AEAD Resp Header IV"]);
    let header_ct = Aes128Gcm::new_from_slice(&header_key)
        .unwrap()
        .encrypt(Nonce::from_slice(&header_iv), header.as_ref())
        .unwrap();

    [len_ct, header_ct].concat()
}

struct RequestHeader {
    req_key: [u8; 16],
    req_iv: [u8; 16],
    resp_v: u8,
}

/// Parse the AEAD-sealed request header off the wire:
/// `auth_id(16) || enc_len(18) || conn_nonce(8) || enc_header(N+16)`.
async fn read_vmess_request_header(stream: &mut TcpStream, cmd_key: &[u8; 16]) -> RequestHeader {
    let mut auth_id = [0u8; 16];
    stream.read_exact(&mut auth_id).await.expect("read auth_id");
    let mut enc_len = [0u8; 18];
    stream.read_exact(&mut enc_len).await.expect("read enc_len");
    let mut conn_nonce = [0u8; 8];
    stream
        .read_exact(&mut conn_nonce)
        .await
        .expect("read conn_nonce");

    let length_key = kdf16(
        cmd_key,
        &[b"VMess Header AEAD Key_Length", &auth_id, &conn_nonce],
    );
    let length_iv = kdf12(
        cmd_key,
        &[b"VMess Header AEAD Nonce_Length", &auth_id, &conn_nonce],
    );
    let len_pt = Aes128Gcm::new_from_slice(&length_key)
        .unwrap()
        .decrypt(
            Nonce::from_slice(&length_iv),
            Payload {
                msg: &enc_len,
                aad: &auth_id,
            },
        )
        .expect("decrypt header length block");
    let header_len = u16::from_be_bytes([len_pt[0], len_pt[1]]) as usize;

    let mut enc_header = vec![0u8; header_len + 16];
    stream
        .read_exact(&mut enc_header)
        .await
        .expect("read enc_header");
    let header_key = kdf16(cmd_key, &[b"VMess Header AEAD Key", &auth_id, &conn_nonce]);
    let header_iv = kdf12(
        cmd_key,
        &[b"VMess Header AEAD Nonce", &auth_id, &conn_nonce],
    );
    let header = Aes128Gcm::new_from_slice(&header_key)
        .unwrap()
        .decrypt(
            Nonce::from_slice(&header_iv),
            Payload {
                msg: &enc_header,
                aad: &auth_id,
            },
        )
        .expect("decrypt request header");

    let mut req_iv = [0u8; 16];
    req_iv.copy_from_slice(&header[1..17]);
    let mut req_key = [0u8; 16];
    req_key.copy_from_slice(&header[17..33]);
    RequestHeader {
        req_key,
        req_iv,
        resp_v: header[33],
    }
}

fn test_uuid() -> [u8; 16] {
    std::array::from_fn(|i| (i + 1) as u8)
}

// ─── The test ────────────────────────────────────────────────────────────────

// The relay emits one wire record per read off the duplex, so record sizes are
// not controlled from the app side. Small chunks plus a yield after each write
// keep reads tracking writes ~1:1, which is what makes the record count a usable
// proxy for the counter value.
const CHUNK: usize = 32;
const MAX_WRITES: usize = 2_000_000;

#[tokio::test]
async fn body_records_stop_at_the_nonce_budget_and_retire_the_connection() {
    let uuid = test_uuid();
    let cmd_key = cmd_key(&uuid);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    // Released once the server hits EOF, so the write pump below stops as soon
    // as the relay has retired the connection.
    let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let hdr = tokio::time::timeout(
            Duration::from_secs(10),
            read_vmess_request_header(&mut stream, &cmd_key),
        )
        .await
        .expect("request header did not arrive in time");

        stream
            .write_all(&seal_response_header(&hdr.req_key, &hdr.req_iv, hdr.resp_v))
            .await
            .unwrap();

        let cipher = Aes128Gcm::new_from_slice(&hdr.req_key).unwrap();
        let mut count = 0usize;

        loop {
            let mut len_buf = [0u8; 2];
            if stream.read_exact(&mut len_buf).await.is_err() {
                break; // EOF between records
            }
            let ct_len = u16::from_be_bytes(len_buf) as usize;
            let mut ct = vec![0u8; ct_len];
            if stream.read_exact(&mut ct).await.is_err() {
                break; // EOF mid-record
            }
            count += 1;

            // A record past the budget can only have been sealed with a counter
            // that already wrapped — and it would still decrypt, which is exactly
            // why the count and not the decryption is the assertion here.
            assert!(
                count <= MAX_RECORDS,
                "record {count} was sent under a reused AEAD (key, nonce): the \
                 body counter wrapped instead of retiring the connection"
            );

            // Every record must still authenticate under its own sequential
            // counter, so the budget is enforced without touching the wire format.
            let counter = u16::try_from(count - 1).unwrap();
            cipher
                .decrypt(
                    Nonce::from_slice(&record_nonce(&hdr.req_iv, counter)),
                    ct.as_slice(),
                )
                .unwrap_or_else(|_| panic!("record {count} must decrypt under counter {counter}"));
        }

        // Let the writer stop before asserting, so a failure here is reported
        // rather than racing a blocked write pump.
        let _ = stop_tx.send(());

        assert_eq!(
            count, MAX_RECORDS,
            "server saw {count} body records before EOF; the connection must be \
             retired after exactly {MAX_RECORDS}"
        );
    });

    let adapter = VmessAdapter::new(
        "vmess-nonce-budget",
        "127.0.0.1",
        port,
        uuid,
        Security::Aes128Gcm,
        false,
        TransportChain::empty(),
        Arc::new(DirectDialer),
    );
    let metadata = Metadata {
        host: "example.com".into(),
        dst_port: 443,
        ..Default::default()
    };
    let mut conn = adapter.dial_tcp(&metadata).await.expect("dial_tcp");

    let chunk = vec![0u8; CHUNK];
    tokio::time::timeout(Duration::from_secs(180), async {
        for _ in 0..MAX_WRITES {
            tokio::select! {
                biased;
                _ = &mut stop_rx => break,
                r = conn.write_all(&chunk) => {
                    // The relay closes the stream once the budget is spent, so a
                    // write error here is the retirement, not a failure.
                    if r.is_err() {
                        break;
                    }
                }
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("record pump timed out");
    drop(conn);

    server.await.unwrap();
}
