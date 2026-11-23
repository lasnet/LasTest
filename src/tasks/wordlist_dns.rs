//! Private, bounded DNS transport for wordlist discovery. All upstream UDP and
//! TCP requests, including retries and validation, pass the same rate gate.
use super::{discovery, TaskContext};
use anyhow::{Context, Result};
use hickory_resolver::proto::{
    op::{Message, MessageType, ResponseCode},
    rr::{DNSClass, RData, RecordType},
};
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{mpsc, Mutex, Semaphore},
    task::{JoinHandle, JoinSet},
    time::Instant,
};

#[derive(Debug)]
pub(super) struct Answer {
    pub host: String,
    pub family: usize,
    pub ips: Vec<IpAddr>,
    pub error: Option<String>,
}

#[derive(Default)]
pub(super) struct Metrics {
    pub requests: AtomicU64,
    pub failures: AtomicU64,
    pub cache_hits: AtomicU64,
    pub overloaded: AtomicBool,
}

struct Gate {
    next: Instant,
    failures: u32,
}

type ResponseCache = Arc<Mutex<HashMap<(String, usize), (Instant, Message)>>>;

#[derive(Clone)]
struct Transport {
    upstream: SocketAddr,
    deadline: Instant,
    period: Duration,
    gate: Arc<Mutex<Gate>>,
    metrics: Arc<Metrics>,
    events: mpsc::Sender<Answer>,
    ctx: TaskContext,
    domain: String,
    allowed: Arc<HashSet<String>>,
    scope: crate::scope::Scope,
    cache: ResponseCache,
}

pub(super) struct Relay {
    pub address: SocketAddr,
    pub answers: mpsc::Receiver<Answer>,
    pub metrics: Arc<Metrics>,
    task: JoinHandle<()>,
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Relay {
    pub async fn stop(&mut self) {
        self.task.abort();
        let _ = (&mut self.task).await;
    }
    pub async fn start(
        ctx: &TaskContext,
        domain: &str,
        allowed: HashSet<String>,
        deadline: Instant,
    ) -> Result<Self> {
        let udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let address = udp.local_addr()?;
        let tcp = TcpListener::bind(address).await?;
        let (events, answers) = mpsc::channel(256);
        let metrics = Arc::new(Metrics::default());
        let transport = Transport {
            upstream: crate::config::wordlist_resolver_address(&ctx.config.dns_wordlist_resolver)?,
            deadline,
            period: Duration::from_secs_f64(1.0 / f64::from(ctx.config.dns_wordlist_rate)),
            gate: Arc::new(Mutex::new(Gate {
                next: Instant::now(),
                failures: 0,
            })),
            metrics: metrics.clone(),
            events,
            ctx: ctx.clone(),
            domain: domain.into(),
            allowed: Arc::new(allowed),
            scope: ctx.current_scope()?,
            cache: Arc::new(Mutex::new(HashMap::new())),
        };
        let task = tokio::spawn(async move {
            let slots = Arc::new(Semaphore::new(32));
            let mut tasks = JoinSet::new();
            let mut packet = vec![0; 65535];
            loop {
                tokio::select! {
                    received = udp.recv_from(&mut packet) => {
                        let Ok((len, peer)) = received else { break; };
                        let Ok(permit) = slots.clone().try_acquire_owned() else { continue; };
                        let request = packet[..len].to_vec();
                        let (udp, transport) = (udp.clone(), transport.clone());
                        tasks.spawn(async move {
                            let _permit = permit;
                            if let Ok(reply) = transport.exchange(&request, false).await {
                                let _ = udp.send_to(&reply, peer).await;
                            }
                        });
                    }
                    accepted = tcp.accept() => {
                        let Ok((mut client, _)) = accepted else { break; };
                        let Ok(permit) = slots.clone().try_acquire_owned() else { continue; };
                        let transport = transport.clone();
                        tasks.spawn(async move {
                            let _permit = permit;
                            let work = async {
                                let len = client.read_u16().await?;
                                anyhow::ensure!(len <= 4096, "DNS query is too large");
                                let mut request = vec![0; usize::from(len)];
                                client.read_exact(&mut request).await?;
                                let reply = transport.exchange(&request, true).await?;
                                client.write_u16(reply.len() as u16).await?;
                                client.write_all(&reply).await?;
                                Ok::<_, anyhow::Error>(())
                            };
                            let _ = tokio::time::timeout(Duration::from_secs(10), work).await;
                        });
                    }
                    _ = tasks.join_next(), if !tasks.is_empty() => {}
                }
            }
        });
        Ok(Self {
            address,
            answers,
            metrics,
            task,
        })
    }
}

impl Transport {
    async fn exchange(&self, packet: &[u8], tcp: bool) -> Result<Vec<u8>> {
        let request = Message::from_vec(packet)?;
        anyhow::ensure!(request.queries().len() == 1, "one DNS question required");
        let query = &request.queries()[0];
        let host = query
            .name()
            .to_utf8()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let family = match query.query_type() {
            RecordType::A => 0,
            RecordType::AAAA => 1,
            _ => return refusal(&request, ResponseCode::Refused),
        };
        if query.query_class() != DNSClass::IN || !self.allowed.contains(&host) {
            return refusal(&request, ResponseCode::Refused);
        }
        self.ctx.ensure_active()?;
        let current = self.ctx.current_scope()?;
        if current.rules != self.scope.rules || Instant::now() >= self.deadline {
            return refusal(&request, ResponseCode::Refused);
        }
        if let Some((until, response)) = self.cache.lock().await.get(&(host.clone(), family)) {
            if *until > Instant::now() {
                let mut response = response.clone();
                response.set_id(request.id());
                *response.queries_mut() = request.queries().to_vec();
                let ttl = until.saturating_duration_since(Instant::now()).as_secs() as u32;
                for record in response.answers_mut() {
                    record.set_ttl(record.ttl().min(ttl));
                }
                for record in response.name_servers_mut() {
                    record.set_ttl(record.ttl().min(ttl));
                }
                self.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
                return Ok(response.to_vec()?);
            }
        }
        let mut gate = self.gate.lock().await;
        tokio::time::sleep_until(gate.next).await;
        self.ctx.ensure_active()?;
        let scope = self.ctx.current_scope()?;
        if Instant::now() >= self.deadline
            || scope.rules != self.scope.rules
            || !discovery::allows_dns_in(&self.ctx.scope.snapshot, &scope, &self.domain, &host)
            || self.metrics.overloaded.load(Ordering::Relaxed)
        {
            return refusal(&request, ResponseCode::Refused);
        }
        self.metrics.requests.fetch_add(1, Ordering::Relaxed);
        let received = tokio::time::timeout(Duration::from_secs(2), async {
            if tcp {
                let mut upstream = TcpStream::connect(self.upstream).await?;
                upstream.write_u16(packet.len() as u16).await?;
                upstream.write_all(packet).await?;
                gate.next = Instant::now() + self.period;
                drop(gate);
                let len = upstream.read_u16().await?;
                let mut reply = vec![0; usize::from(len)];
                upstream.read_exact(&mut reply).await?;
                Ok::<_, anyhow::Error>(reply)
            } else {
                let bind = if self.upstream.is_ipv4() {
                    "0.0.0.0:0"
                } else {
                    "[::]:0"
                };
                let upstream = UdpSocket::bind(bind).await?;
                upstream.connect(self.upstream).await?;
                upstream.send(packet).await?;
                gate.next = Instant::now() + self.period;
                drop(gate);
                let mut reply = vec![0; 65535];
                let len = upstream.recv(&mut reply).await?;
                reply.truncate(len);
                Ok(reply)
            }
        })
        .await;
        let received = received
            .map_err(|_| anyhow::anyhow!("DNS resolver timed out"))
            .and_then(|r| r);
        let parsed = received.and_then(|bytes| {
            let response = Message::from_vec(&bytes)?;
            anyhow::ensure!(
                response.id() == request.id()
                    && response.message_type() == MessageType::Response
                    && response.queries() == request.queries(),
                "DNS resolver returned a mismatched reply"
            );
            Ok((bytes, response))
        });
        let mut answer = Answer {
            host,
            family,
            ips: Vec::new(),
            error: None,
        };
        let bytes = match parsed {
            Ok((bytes, response)) => {
                // TCP fallback must not count a truncated UDP answer as NODATA.
                if response.truncated() {
                    return Ok(bytes);
                }
                if matches!(
                    response.response_code(),
                    ResponseCode::NoError | ResponseCode::NXDomain
                ) {
                    // dnsx retries negative answers too. Reuse only TTL-bearing
                    // answers, per family; never turn a timeout into NXDOMAIN.
                    let ttl = response
                        .answers()
                        .iter()
                        .map(|r| r.ttl())
                        .chain(
                            response
                                .name_servers()
                                .iter()
                                .filter_map(|r| match r.data() {
                                    Some(RData::SOA(soa)) => Some(r.ttl().min(soa.minimum())),
                                    _ => None,
                                }),
                        )
                        .min()
                        .unwrap_or(0)
                        .min(60);
                    if ttl > 0 {
                        self.cache.lock().await.insert(
                            (answer.host.clone(), family),
                            (
                                Instant::now() + Duration::from_secs(u64::from(ttl)),
                                response.clone(),
                            ),
                        );
                    }
                }
                match response.response_code() {
                    ResponseCode::NoError => {
                        let mut owners = HashSet::from([query.name().clone()]);
                        for _ in 0..16 {
                            let before = owners.len();
                            for record in response.answers() {
                                if owners.contains(record.name()) {
                                    if let Some(RData::CNAME(name)) = record.data() {
                                        owners.insert(name.0.clone());
                                    }
                                }
                            }
                            if owners.len() == before {
                                break;
                            }
                        }
                        for record in response.answers() {
                            if owners.contains(record.name()) && record.dns_class() == DNSClass::IN
                            {
                                match record.data() {
                                    Some(RData::A(ip)) if family == 0 => {
                                        answer.ips.push(ip.0.into())
                                    }
                                    Some(RData::AAAA(ip)) if family == 1 => {
                                        answer.ips.push(ip.0.into())
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    ResponseCode::NXDomain => {}
                    code => answer.error = Some(format!("DNS resolver returned {code}")),
                }
                bytes
            }
            Err(error) => {
                answer.error = Some(error.to_string());
                refusal(&request, ResponseCode::ServFail)?
            }
        };
        {
            let mut gate = self.gate.lock().await;
            if answer.error.is_some() {
                self.metrics.failures.fetch_add(1, Ordering::Relaxed);
                gate.failures += 1;
                let backoff = Duration::from_millis((100u64 << gate.failures.min(5)).min(5000));
                gate.next = gate.next.max(Instant::now() + backoff);
                if gate.failures >= 8 {
                    self.metrics.overloaded.store(true, Ordering::Relaxed);
                }
            } else {
                gate.failures = 0;
            }
        }
        self.events
            .send(answer)
            .await
            .context("wordlist receiver stopped")?;
        Ok(bytes)
    }
}

fn refusal(request: &Message, code: ResponseCode) -> Result<Vec<u8>> {
    let mut response = Message::new();
    response
        .set_id(request.id())
        .set_message_type(MessageType::Response)
        .set_recursion_desired(request.recursion_desired())
        .set_recursion_available(true)
        .set_response_code(code);
    response.add_queries(request.queries().iter().cloned());
    Ok(response.to_vec()?)
}
