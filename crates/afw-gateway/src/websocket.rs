//! WebSocket relay with inspection (EF-24): the upgrade is forwarded on a dedicated
//! HTTP/1.1 upstream connection, then agent-to-upstream frames are parsed. Each complete
//! message is analysed (with an overlap window over the previous messages, so a value split
//! across messages is found) before any of its frames is relayed; a detection that the policy
//! denies cuts both sides (close 1008 to the agent). LLM provider destinations are exempt
//! from data-class blocking through the engine (EF-25). Upstream-to-agent data is relayed as is.

use std::net::SocketAddr;
use std::sync::Arc;

use afw_core::events::Verdict;
use http::{Request, Response, StatusCode, Version};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::engine::Decision;
use crate::http_pipeline::{ContentJudge, GwBody, HttpFlow, HttpLog, full, open_upstream};

fn bad_gateway(text: &str) -> Response<GwBody> {
    Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .header("x-agents-firewall", "error")
        .body(full(format!("agents-firewall: {text}")))
        .expect("static response")
}

pub async fn handle(
    hf: Arc<HttpFlow>,
    mut req: Request<Incoming>,
    upstream: SocketAddr,
    decision: Decision,
    judge: ContentJudge,
    mut log: HttpLog,
) -> Response<GwBody> {
    let state = hf.state().clone();
    let flow = hf.flow.clone();
    let client_upgrade = hyper::upgrade::on(&mut req);
    let tls = hf.tls.then(|| {
        (
            flow.name
                .clone()
                .unwrap_or_else(|| upstream.ip().to_string()),
            state.upstream_tls_h1.clone(),
        )
    });
    let (stream, _) = match open_upstream(upstream, tls).await {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!(error = %e, "websocket upstream connect failed");
            log.emit(None, vec![]);
            return bad_gateway("upstream unreachable");
        }
    };
    let (mut sender, conn) = match hyper::client::conn::http1::Builder::new()
        .handshake::<_, GwBody>(TokioIo::new(stream))
        .await
    {
        Ok(x) => x,
        Err(_) => return bad_gateway("upstream handshake failed"),
    };
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });
    let (mut parts, _) = req.into_parts();
    parts.version = Version::HTTP_11;
    parts.uri = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/")
        .parse()
        .unwrap_or_default();
    parts.headers.remove("proxy-connection");
    // No extension (permessage-deflate would hide the payload from the analysis).
    parts.headers.remove("sec-websocket-extensions");
    parts.headers.remove("proxy-authorization");
    let mut resp = match sender
        .send_request(Request::from_parts(parts, full("")))
        .await
    {
        Ok(r) => r,
        Err(_) => return bad_gateway("upstream request failed"),
    };
    log.ev.status = Some(resp.status().as_u16());
    flow.mark_allowed(&decision);
    if resp.status() != StatusCode::SWITCHING_PROTOCOLS {
        log.emit(None, vec![]);
        let (parts, body) = resp.into_parts();
        return Response::from_parts(parts, body.map_err(|e| Box::new(e) as _).boxed());
    }
    let upstream_upgrade = hyper::upgrade::on(&mut resp);
    log.emit(None, vec![]);
    let max_msg = state.store.current().settings().max_buffered_body as usize;
    let flow2 = flow.clone();
    tokio::spawn(async move {
        let (Ok(agent), Ok(up)) = (client_upgrade.await, upstream_upgrade.await) else {
            return;
        };
        relay(TokioIo::new(agent), TokioIo::new(up), judge, max_msg).await;
        drop(flow2);
    });
    let (parts, _) = resp.into_parts();
    Response::from_parts(parts, full(""))
}

/// Bytes of previous messages rescanned with the next one.
const WS_CARRY: usize = 8 * 1024;

enum End {
    Closed,
    /// Frame with a reserved bit set (no extension was negotiated): protocol error 1002.
    Protocol,
    Cut(Option<Decision>),
}

async fn relay<A, U>(agent: A, up: U, judge: ContentJudge, max_msg: usize)
where
    A: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let (mut ar, mut aw) = tokio::io::split(agent);
    let (mut ur, mut uw) = tokio::io::split(up);
    let end = tokio::select! {
        e = agent_to_upstream(&mut ar, &mut uw, &judge, max_msg) => e,
        _ = tokio::io::copy(&mut ur, &mut aw) => End::Closed,
    };
    if let End::Protocol = end {
        let _ = aw
            .write_all(&close_frame(
                1002,
                "agents-firewall: websocket extensions are not allowed",
            ))
            .await;
        let _ = aw.flush().await;
        let _ = aw.shutdown().await;
        let _ = uw.shutdown().await;
        return;
    }
    if let End::Cut(d) = end {
        let reason = match &d {
            Some(d) => d.deny_message(&judge.destination),
            None => "blocked by agents-firewall: message too large to inspect".to_string(),
        };
        let _ = aw.write_all(&close_frame(1008, &reason)).await;
        let _ = aw.flush().await;
        let _ = aw.shutdown().await;
        let _ = uw.shutdown().await;
        if let Some(d) = d {
            let mut d = d;
            d.verdict = Verdict::Deny;
            judge_flow_deny(&judge, &d);
        }
    }
}

fn judge_flow_deny(judge: &ContentJudge, d: &Decision) {
    judge
        .state
        .metrics
        .denied_total
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    judge.state.alerts.on_deny(d.agent_id);
}

/// Close frame (server to client: unmasked).
pub fn close_frame(code: u16, reason: &str) -> Vec<u8> {
    let mut payload = code.to_be_bytes().to_vec();
    let r = reason.as_bytes();
    payload.extend_from_slice(&r[..r.len().min(123)]);
    let mut f = vec![0x88, payload.len() as u8];
    f.extend_from_slice(&payload);
    f
}

struct RawFrame {
    raw: Vec<u8>,
    opcode: u8,
    fin: bool,
    rsv: u8,
    payload: Vec<u8>,
}

/// Reads one frame; `Err(true)` when it exceeds `max` (cut), `Err(false)` on EOF/error.
async fn read_frame<R: AsyncRead + Unpin>(r: &mut R, max: usize) -> Result<RawFrame, bool> {
    let mut h = [0u8; 2];
    r.read_exact(&mut h).await.map_err(|_| false)?;
    let mut raw = h.to_vec();
    let masked = h[1] & 0x80 != 0;
    let mut len = (h[1] & 0x7f) as u64;
    if len == 126 {
        let mut b = [0u8; 2];
        r.read_exact(&mut b).await.map_err(|_| false)?;
        raw.extend_from_slice(&b);
        len = u16::from_be_bytes(b) as u64;
    } else if len == 127 {
        let mut b = [0u8; 8];
        r.read_exact(&mut b).await.map_err(|_| false)?;
        raw.extend_from_slice(&b);
        len = u64::from_be_bytes(b);
    }
    if len > max as u64 {
        return Err(true);
    }
    let mut key = [0u8; 4];
    if masked {
        r.read_exact(&mut key).await.map_err(|_| false)?;
        raw.extend_from_slice(&key);
    }
    let mut payload = vec![0u8; len as usize];
    r.read_exact(&mut payload).await.map_err(|_| false)?;
    raw.extend_from_slice(&payload);
    if masked {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= key[i % 4];
        }
    }
    Ok(RawFrame {
        raw,
        opcode: h[0] & 0x0f,
        fin: h[0] & 0x80 != 0,
        rsv: h[0] & 0x70,
        payload,
    })
}

async fn agent_to_upstream<R, W>(
    ar: &mut R,
    uw: &mut W,
    judge: &ContentJudge,
    max_msg: usize,
) -> End
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let scanner = judge.state.store.current().scanner.clone();
    // Tail of the previous messages, rescanned with each new message so that a value split
    // across messages is found before the message completing it is relayed.
    let mut carry: Vec<u8> = Vec::new();
    let mut msg: Vec<u8> = Vec::new();
    let mut held: Vec<Vec<u8>> = Vec::new();
    let mut msg_len = 0usize;
    let mut findings = Vec::new();
    loop {
        let f = match read_frame(ar, max_msg).await {
            Ok(f) => f,
            Err(true) => return End::Cut(None),
            Err(false) => return End::Closed,
        };
        if f.rsv != 0 {
            return End::Protocol;
        }
        if f.opcode >= 0x8 {
            // Control frames (ping/pong/close, <= 125 bytes) are analysed on their own.
            let found = scanner.scan(&f.payload, "websocket.control");
            if !found.is_empty() {
                findings.extend(found);
                let (d, blocked) = judge.judge(&findings);
                if blocked {
                    return End::Cut(Some(d));
                }
            }
            if uw.write_all(&f.raw).await.is_err() {
                return End::Closed;
            }
            if f.opcode == 0x8 {
                let _ = uw.flush().await;
                return End::Closed;
            }
            continue;
        }
        msg_len += f.payload.len();
        if msg_len > max_msg {
            return End::Cut(None);
        }
        msg.extend_from_slice(&f.payload);
        held.push(f.raw);
        if f.fin {
            let mut window = std::mem::take(&mut carry);
            let tail = window.len();
            window.extend_from_slice(&msg);
            msg.clear();
            let found: Vec<_> = scanner
                .scan(&window, "websocket.message")
                .into_iter()
                .filter(|x| x.end > tail)
                .collect();
            if !found.is_empty() {
                findings.extend(found);
                let (d, blocked) = judge.judge(&findings);
                if blocked {
                    return End::Cut(Some(d));
                }
            }
            let keep = window.len().min(WS_CARRY);
            carry = window.split_off(window.len() - keep);
            for raw in held.drain(..) {
                if uw.write_all(&raw).await.is_err() {
                    return End::Closed;
                }
            }
            if uw.flush().await.is_err() {
                return End::Closed;
            }
            msg_len = 0;
        }
    }
}
