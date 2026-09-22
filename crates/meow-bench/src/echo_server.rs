use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

pub async fn start_echo_server() -> anyhow::Result<(SocketAddr, JoinHandle<()>)> {
    start_echo_server_on("127.0.0.1:0".parse()?).await
}

/// Same echo server bound to a specific address — the reload workload's
/// datapath probe needs a fixed port the benchmark configs can name in a
/// `DST-PORT` rule.
pub async fn start_echo_server_on(
    addr: SocketAddr,
) -> anyhow::Result<(SocketAddr, JoinHandle<()>)> {
    let listener = TcpListener::bind(addr).await?;
    let addr = listener.local_addr()?;

    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                // A persistent accept error (e.g. EMFILE when the harness
                // process itself is near its fd cap) would otherwise turn
                // this into a hot spin burning a worker thread's CPU
                // during the measurement window.
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                continue;
            };
            tokio::spawn(async move {
                let (mut rd, mut wr) = tokio::io::split(stream);
                let _ = tokio::io::copy(&mut rd, &mut wr).await;
            });
        }
    });

    Ok((addr, handle))
}
