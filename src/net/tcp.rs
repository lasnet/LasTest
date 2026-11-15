use crate::scope::NetworkPolicy;
use anyhow::Result;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeState {
    Open,
    Closed,
    Timeout,
    Error,
}

impl ProbeState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Closed => "closed",
            Self::Timeout => "timeout",
            Self::Error => "error",
        }
    }
}

#[derive(Debug, Clone)]
pub struct TcpProbe {
    pub ip: IpAddr,
    pub port: u16,
    pub state: ProbeState,
    pub duration_ms: u128,
    pub error: Option<String>,
}

pub async fn probe_tcp(
    ip: IpAddr,
    port: u16,
    timeout: Duration,
    policy: &NetworkPolicy,
) -> Result<TcpProbe> {
    policy.permits(ip)?;
    let started = std::time::Instant::now();
    let result = tokio::time::timeout(
        timeout,
        tokio::net::TcpStream::connect(SocketAddr::new(ip, port)),
    )
    .await;
    let duration_ms = started.elapsed().as_millis();
    let (state, error) = match result {
        Ok(Ok(_stream)) => (ProbeState::Open, None),
        Ok(Err(err)) => {
            let kind = err.kind();
            let message = err.to_string();
            if kind == std::io::ErrorKind::TimedOut {
                (ProbeState::Timeout, Some(message))
            } else {
                (ProbeState::Closed, Some(message))
            }
        }
        Err(_) => (
            ProbeState::Timeout,
            Some("connection timed out".to_string()),
        ),
    };
    Ok(TcpProbe {
        ip,
        port,
        state,
        duration_ms,
        error,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn local_listener_and_closed_port_are_distinct() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let policy = NetworkPolicy::new(vec!["127.0.0.0/8".parse().unwrap()]);
        let open = probe_tcp(
            "127.0.0.1".parse().unwrap(),
            port,
            Duration::from_secs(2),
            &policy,
        )
        .await
        .unwrap();
        assert_eq!(open.state, ProbeState::Open);
        let (closed_port, _) = {
            let second = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let p = second.local_addr().unwrap().port();
            drop(second);
            (p, ())
        };
        let closed = probe_tcp(
            "127.0.0.1".parse().unwrap(),
            closed_port,
            Duration::from_millis(500),
            &policy,
        )
        .await
        .unwrap();
        assert_ne!(closed.state, ProbeState::Open);
    }
}
