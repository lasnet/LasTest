//! Shared bounded DNS, HTTP and TCP clients. Every active client receives an
//! already-authorized target and a network policy.

pub mod dns;
pub mod http;
pub mod socks;
pub mod tcp;

pub use dns::DnsClient;
pub use http::HttpProber;
pub use socks::connect_via_socks5;
pub use tcp::{probe_tcp, ProbeState, TcpProbe};
