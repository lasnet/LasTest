//! Minimal SOCKS5 client. The target is always passed as a validated IP so the
//! proxy cannot re-resolve a hostname that DNS pinning already checked.

use crate::config::Socks5Profile;
use anyhow::{Context, Result};
use std::net::IpAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub async fn connect_via_socks5(
    profile: &Socks5Profile,
    target: IpAddr,
    target_port: u16,
    timeout: Duration,
) -> Result<TcpStream> {
    let exchange = async {
        let mut stream = TcpStream::connect((profile.host.as_str(), profile.port)).await?;
        let has_auth = profile.username.is_some() || profile.password.is_some();
        if has_auth {
            stream.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;
        } else {
            stream.write_all(&[0x05, 0x01, 0x00]).await?;
        }
        let mut choice = [0u8; 2];
        stream.read_exact(&mut choice).await?;
        if choice[0] != 0x05 {
            anyhow::bail!("proxy did not speak SOCKS5");
        }
        match choice[1] {
            0x00 => {}
            0x02 => {
                let username = profile.username.as_deref().unwrap_or("");
                let password = profile.password.as_deref().unwrap_or("");
                if username.len() > 255 || password.len() > 255 {
                    anyhow::bail!("SOCKS5 credentials are too long");
                }
                let mut auth = vec![0x01, username.len() as u8];
                auth.extend_from_slice(username.as_bytes());
                auth.push(password.len() as u8);
                auth.extend_from_slice(password.as_bytes());
                stream.write_all(&auth).await?;
                let mut reply = [0u8; 2];
                stream.read_exact(&mut reply).await?;
                if reply[1] != 0x00 {
                    anyhow::bail!("SOCKS5 authentication failed");
                }
            }
            0xff => anyhow::bail!("proxy rejected authentication methods"),
            other => anyhow::bail!("unsupported SOCKS5 auth method: {other}"),
        }
        let mut request = vec![0x05, 0x01, 0x00];
        match target {
            IpAddr::V4(v4) => {
                request.push(0x01);
                request.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                request.push(0x04);
                request.extend_from_slice(&v6.octets());
            }
        }
        request.extend_from_slice(&target_port.to_be_bytes());
        stream.write_all(&request).await?;
        let mut head = [0u8; 4];
        stream.read_exact(&mut head).await?;
        if head[0] != 0x05 || head[1] != 0x00 {
            anyhow::bail!("SOCKS5 connect failed with code {}", head[1]);
        }
        match head[3] {
            0x01 => {
                let mut skip = [0u8; 4 + 2];
                stream.read_exact(&mut skip).await?;
            }
            0x04 => {
                let mut skip = [0u8; 16 + 2];
                stream.read_exact(&mut skip).await?;
            }
            0x03 => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await?;
                let mut skip = vec![0u8; len[0] as usize + 2];
                stream.read_exact(&mut skip).await?;
            }
            other => anyhow::bail!("invalid SOCKS5 address type: {other}"),
        }
        Ok(stream)
    };
    tokio::time::timeout(timeout, exchange)
        .await
        .map_err(|_| anyhow::anyhow!("SOCKS5 connection timed out"))?
        .with_context(|| format!("SOCKS5 proxy '{}' failed", profile.name))
}
