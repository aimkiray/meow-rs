pub mod cache;
pub mod client;
pub mod fakeip;
pub mod host_resolver_hook;
pub mod resolver;
pub mod server;
pub mod upstream;

pub use cache::{DnsCache, DnsCacheSnapshotEntry, ReverseSnapshotEntry};
pub use client::{set_socket_factory, ClientError, DnsClient, SocketFactory};
pub use fakeip::{FileStore, MemoryStore, Pool, PoolError, Skipper, SkipperMode, Store};
pub use host_resolver_hook::ResolverHostHook;
pub use resolver::{BootstrapError, FallbackFilter, NameserverPolicy, PolicyEntry, Resolver};
pub use server::{BoundDnsServer, DnsServer};
pub use upstream::{HostOrIp, NameServerEntry, NameServerParseError, NameServerUrl};

use std::sync::atomic::{AtomicBool, Ordering};

static IPV6_DISABLED: AtomicBool = AtomicBool::new(false);

/// When true, DnsClient::lookup_ip skips AAAA queries entirely and
/// only resolves A records.  Set by the Android FFI bridge from the
/// "Disable IPv6" user setting so the resolver doesn't return IPv6
/// addresses that the VPN has no route for.
pub fn set_ipv6_disabled(disabled: bool) {
    IPV6_DISABLED.store(disabled, Ordering::Relaxed);
}

pub fn ipv6_disabled() -> bool {
    IPV6_DISABLED.load(Ordering::Relaxed)
}
