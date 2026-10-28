use meow_common::MeowError;

// Downstream exhaustive matches are part of the public API contract.
#[test]
fn meow_error_remains_exhaustive() {
    fn classify(error: MeowError) {
        match error {
            MeowError::Io(_)
            | MeowError::Config(_)
            | MeowError::Dns(_)
            | MeowError::Proxy(_)
            | MeowError::NotSupported(_)
            | MeowError::ProxyAuthFailed
            | MeowError::HttpConnectFailed(_)
            | MeowError::Socks5ConnectFailed(_)
            | MeowError::NoAcceptableMethod
            | MeowError::NoProxyAvailable
            | MeowError::RelayHopFailed { .. }
            | MeowError::UdpNotSupported
            | MeowError::Other(_) => (),
        }
    }
    classify(MeowError::Config("test".into()));
}
