//! 55AA 易支付网关：epay(MD5) 协议 ↔ 可插拔支付 provider。
//!
//! 路由：
//!   GET|POST /submit.php        new-api 发起支付（epay 签名校验 → 建 order → provider 下单 → 二维码页）
//!   GET      /api/order/{no}    收银台轮询（pending 时主动查单兜底，PRD 3.1.7）
//!   POST     /notify/{provider} 渠道回调（验签解密 → mark_paid → epay notify 回发 new-api）
//!   GET      /healthz

mod epay;
mod orders;
mod page;
mod provider;
mod providers;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{any, get, post};
use axum::Router;
use orders::{Order, Store, ST_CLOSED, ST_PAID, ST_PENDING};
use provider::{PayStatus, Payment, Registry};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

struct AppState {
    store: Store,
    registry: Registry,
    epay_pid: String,
    epay_key: String,
    http: reqwest::Client,
    /// 回调基底（如 https://pay.example.com），用于构造微信 notify_url
    notify_base: String,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let bind = std::env::var("BIND_HOST").unwrap_or_else(|_| "127.0.0.1:8787".into());
    let db_path = std::env::var("DB_PATH").unwrap_or_else(|_| "/data/orders.db".into());
    let epay_pid = std::env::var("EPAY_PID").expect("EPAY_PID required");
    let epay_key = std::env::var("EPAY_KEY").expect("EPAY_KEY required");
    let notify_base = std::env::var("NOTIFY_BASE").expect("NOTIFY_BASE required");
    let wechat_cfg = providers::wechat::WechatConfig {
        appid: std::env::var("WXPAY_APPID").expect("WXPAY_APPID required"),
        mch_id: std::env::var("WXPAY_MCH_ID").expect("WXPAY_MCH_ID required"),
        serial_no: std::env::var("WXPAY_SERIAL_NO").expect("WXPAY_SERIAL_NO required"),
        private_key_pem: resolve_private_key_pem(),
        api_v3_key: std::env::var("WXPAY_APIV3_KEY").expect("WXPAY_APIV3_KEY required"),
        api_base: std::env::var("WXPAY_API_BASE")
            .unwrap_or_else(|_| "https://api.mch.weixin.qq.com".into()),
        notify_base: notify_base.clone(),
    };

    let store = Store::open(&db_path).expect("open sqlite");
    let registry = providers::build_registry(wechat_cfg).expect("registry");

    let state = Arc::new(AppState {
        store,
        registry,
        epay_pid,
        epay_key,
        http: reqwest::Client::new(),
        notify_base,
    });

    // 每分钟关闭超时未支付订单（2 小时，PRD 3.1.5）
    let bg_state = state.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            let cutoff = chrono::Utc::now().timestamp() - 2 * 3600;
            if let Ok(n) = bg_state.store.close_expired(cutoff) {
                if n > 0 {
                    tracing::info!("closed {n} expired orders");
                }
            }
        }
    });

    let app = Router::new()
        .route("/submit.php", any(submit))
        .route("/api/order/{out_trade_no}", get(order_status))
        .route("/notify/{provider}", post(channel_notify))
        .route("/healthz", get(healthz))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&bind).await.expect("bind");
    tracing::info!("pay-gateway listening on {bind}");
    axum::serve(listener, app).await.unwrap();
}

/// 商户私钥三种填法（按优先级）：
/// 1. WXPAY_PRIVATE_KEY_FILE=/path/apiclient_key.pem（推荐，文件直读）
/// 2. WXPAY_PRIVATE_KEY_FILE_B64=base64(整段 PEM)（scp 不便时）
/// 3. WXPAY_PRIVATE_KEY=单行 PEM（换行写作 \n，此字段自动还原）
fn resolve_private_key_pem() -> String {
    if let Ok(path) = std::env::var("WXPAY_PRIVATE_KEY_FILE") {
        return std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {path}: {e}"));
    }
    if let Ok(b64) = std::env::var("WXPAY_PRIVATE_KEY_FILE_B64") {
        use base64::Engine;
        return base64::engine::general_purpose::STANDARD
            .decode(b64.trim())
            .map(|b| String::from_utf8(b).expect("pem utf8"))
            .expect("decode WXPAY_PRIVATE_KEY_FILE_B64");
    }
    let inline = std::env::var("WXPAY_PRIVATE_KEY").expect("set WXPAY_PRIVATE_KEY_FILE or WXPAY_PRIVATE_KEY");
    inline.replace("\\n", "\n")
}

async fn healthz() -> &'static str {
    "ok"
}

/// new-api 发起支付（epay 协议）。参数可经 query 或 form。
async fn submit(
    State(st): State<Arc<AppState>>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // 合并 query 与 form 参数（go-epay 客户端用 GET；也兼容 POST form）
    let mut params: Vec<(String, String)> = q.into_iter().collect();
    if headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.starts_with("application/x-www-form-urlencoded"))
        .unwrap_or(false)
        && !body.is_empty()
    {
        if let Ok(form) = url_decode_body(&body) {
            params.extend(form);
        }
    }

    let get = |k: &str| params.iter().find(|(pk, _)| pk == k).map(|(_, v)| v.clone());

    let out_trade_no = get("out_trade_no").unwrap_or_default();
    let money = get("money").unwrap_or_default();
    let name = get("name").unwrap_or_default();
    let epay_type = get("type").unwrap_or_default();
    let notify_url = get("notify_url").unwrap_or_default();
    let return_url = get("return_url").unwrap_or_default();

    if out_trade_no.is_empty() || money.is_empty() || notify_url.is_empty() {
        return (StatusCode::BAD_REQUEST, "missing required params").into_response();
    }
    // 验签（PRD 3.1.7：验签失败拒绝）
    match epay::verify(&params, &st.epay_key) {
        Ok(true) => {}
        Ok(false) => {
            tracing::warn!("epay sign verify failed for {out_trade_no}");
            return (StatusCode::FORBIDDEN, "sign verify failed").into_response();
        }
        Err(e) => return (StatusCode::BAD_REQUEST, format!("bad params: {e}")).into_response(),
    }
    if !st.registry.by_epay_type(&epay_type).is_some() {
        return (StatusCode::BAD_REQUEST, format!("unknown pay type {epay_type}")).into_response();
    }

    let money_cents: i64 = match (money.parse::<f64>(), money.parse::<i64>()) {
        (Ok(f), _) if f > 0.0 => (f * 100.0).round() as i64,
        (_, Ok(i)) if i > 0 => i,
        _ => return (StatusCode::BAD_REQUEST, "bad money").into_response(),
    };

    let provider = st.registry.by_epay_type(&epay_type).unwrap();
    let created = provider
        .create_payment(provider::CreatePayment {
            out_trade_no: out_trade_no.clone(),
            amount_cents: money_cents,
            subject: if name.is_empty() { "55AA 充值".into() } else { name.clone() },
            notify_url: format!("{}/notify/{}", st.notify_base, provider.name()),
        })
        .await;

    let payment = match created {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("create payment failed for {out_trade_no}: {e}");
            return (StatusCode::BAD_GATEWAY, format!("upstream error: {e}")).into_response();
        }
    };

    let order = Order {
        out_trade_no: out_trade_no.clone(),
        provider: provider.name().to_string(),
        epay_type: epay_type.clone(),
        money_cents,
        subject: name.clone(),
        notify_url,
        return_url,
        status: ST_PENDING,
        trade_no: None,
        paid_at: None,
        created_at: chrono::Utc::now().timestamp(),
        notified: false,
    };
    if let Err(e) = st.store.insert(&order) {
        if !format!("{e}").contains("UNIQUE") {
            tracing::error!("insert order {out_trade_no}: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "store error").into_response();
        }
        // 重复 submit 同一订单号：已有订单，直接复用（幂等）
    }

    match payment {
        Payment::Qr { code_url } => {
            let money_yuan = format!("{:.2}", money_cents as f64 / 100.0);
            // PRD 3.1.4：支付成功回到钱包页。new-api 上游 return_url 写死 /usage-logs，
            // 网关侧用 RETURN_PATH 覆盖（不配置则沿用上游 return_url）
            let return_target = match std::env::var("RETURN_PATH") {
                // 完整 URL（含站点），如 https://<控制台域名>/console/topup
                Ok(p) if !p.is_empty() => p,
                _ => order.return_url.clone(),
            };
            Html(page::cashier_html_with_qr(
                &out_trade_no,
                &order.subject,
                &money_yuan,
                &return_target,
                &code_url,
            ))
            .into_response()
        }
        Payment::Redirect { url } => {
            Response::builder()
                .status(StatusCode::FOUND)
                .header("Location", url)
                .body(axum::body::Body::empty())
                .unwrap()
        }
    }
}

/// 收银台轮询。pending 时主动查单兜底（PRD 3.1.7：回调丢失场景）。
async fn order_status(
    State(st): State<Arc<AppState>>,
    Path(out_trade_no): Path<String>,
) -> Response {
    let Some(order) = st.store.get(&out_trade_no).ok().flatten() else {
        return (StatusCode::NOT_FOUND, "order not found").into_response();
    };
    let mut status = order.status;
    if status == ST_PENDING {
        if let Some(p) = st.registry.by_name(&order.provider) {
            match p.query_status(&out_trade_no).await {
                Ok(PayStatus::Paid { trade_no }) => {
                    if st.store.mark_paid(&out_trade_no, &trade_no, chrono::Utc::now().timestamp()).unwrap_or(false) {
                        spawn_notify_new_api(st.clone(), &out_trade_no);
                    }
                    status = ST_PAID;
                }
                Ok(PayStatus::Closed) => {
                    st.store.set_status(&out_trade_no, ST_CLOSED).ok();
                    status = ST_CLOSED;
                }
                _ => {}
            }
        }
    }
    (
        [(header_content_type(), "application/json")],
        axum::Json(json!({
            "out_trade_no": out_trade_no,
            "status": match status {
                ST_PAID => "paid",
                ST_CLOSED => "closed",
                orders::ST_ABNORMAL => "abnormal",
                _ => "pending",
            },
        })),
    )
        .into_response()
}

/// 渠道回调：验签 → 幂等入账 → epay notify 回发 new-api → 按渠道要求应答
async fn channel_notify(
    State(st): State<Arc<AppState>>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(provider) = st.registry.by_name(&name) else {
        return (StatusCode::NOT_FOUND, "unknown provider").into_response();
    };
    let cb = match provider.handle_callback(&headers, &body).await {
        Ok(cb) => cb,
        Err(e) => {
            // PRD 3.1.7：验签失败拒绝并记录告警日志
            tracing::warn!("channel {name} callback rejected: {e}");
            return wechat_ack(false);
        }
    };

    let Some(order) = st.store.get(&cb.out_trade_no).ok().flatten() else {
        tracing::warn!("callback for unknown order {}", cb.out_trade_no);
        return wechat_ack(true); // 未知订单：应答成功避免重推风暴，同时记录
    };
    // PRD 3.1.7：金额不一致 → 拒绝入账，标记异常，人工介入
    if cb.amount_cents != order.money_cents {
        tracing::error!(
            "amount mismatch for {}: channel {} vs order {}",
            cb.out_trade_no, cb.amount_cents, order.money_cents
        );
        st.store.set_status(&cb.out_trade_no, orders::ST_ABNORMAL).ok();
        return wechat_ack(true);
    }
    if st.store.mark_paid(&cb.out_trade_no, &cb.trade_no, chrono::Utc::now().timestamp()).unwrap_or(false) {
        tracing::info!("order {} paid via {name}", cb.out_trade_no);
        spawn_notify_new_api(st.clone(), &cb.out_trade_no);
    }
    wechat_ack(true)
}

/// epay 协议回发 new-api notify_url（GET + MD5 签名，带重试）
fn spawn_notify_new_api(st: Arc<AppState>, out_trade_no: &str) {
    let st = st.clone();
    let out_trade_no = out_trade_no.to_string();
    tokio::spawn(async move {
        let Some(order) = st.store.get(&out_trade_no).ok().flatten() else { return };
        let params = vec![
            ("trade_no".to_string(), order.trade_no.clone().unwrap_or_default()),
            ("out_trade_no".to_string(), order.out_trade_no.clone()),
            ("type".to_string(), order.epay_type.clone()),
            ("name".to_string(), order.subject.clone()),
            ("money".to_string(), format!("{:.2}", order.money_cents as f64 / 100.0)),
            ("trade_status".to_string(), "TRADE_SUCCESS".to_string()),
            ("param".to_string(), String::new()),
        ];
        let signed = match epay::generate_signed(params, &st.epay_pid, &st.epay_key) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("build notify params: {e}");
                return;
            }
        };
        let qs: Vec<String> = signed
            .iter()
            .map(|(k, v)| format!("{k}={}", urlencoding_lite(v)))
            .collect();
        let url = format!("{}?{}", order.notify_url, qs.join("&"));
        for attempt in 1..=5 {
            match st.http.get(&url).timeout(Duration::from_secs(10)).send().await {
                Ok(resp) if resp.status().is_success() => {
                    // 抢通知权：失败说明其他路径已通知（new-api 侧幂等，无害）
                    match st.store.claim_notify(&out_trade_no) {
                        Ok(true) => tracing::info!("notified new-api for {out_trade_no} (attempt {attempt})"),
                        Ok(false) => {}
                        Err(e) => tracing::error!("claim notify {out_trade_no}: {e}"),
                    }
                    return;
                }
                Ok(resp) => tracing::warn!("notify attempt {attempt} status {}", resp.status()),
                Err(e) => tracing::warn!("notify attempt {attempt} error: {e}"),
            }
            tokio::time::sleep(Duration::from_secs(5 * attempt as u64)).await;
        }
        tracing::error!("notify new-api failed after retries for {out_trade_no} — will retry on next poll/callback");
    });
}

fn wechat_ack(success: bool) -> Response {
    let body = if success {
        json!({"code": "SUCCESS", "message": "成功"})
    } else {
        json!({"code": "FAIL", "message": "验证失败"})
    };
    (
        StatusCode::OK,
        [(header_content_type(), "application/json")],
        axum::Json(body),
    )
        .into_response()
}

fn header_content_type() -> &'static str {
    "content-type"
}

/// 极简 application/x-www-form-urlencoded 解析（无百分号解码需求场景仅 sign 校验原样参与；
/// notify_url/money 等 new-api 侧为标准 urlencoded，这里做完整解码）
fn url_decode_body(b: &[u8]) -> Result<Vec<(String, String)>, ()> {
    let s = std::str::from_utf8(b).map_err(|_| ())?;
    Ok(s.split('&')
        .filter(|kv| !kv.is_empty())
        .map(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            (url_decode(k), url_decode(v))
        })
        .collect())
}

fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex_pair = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("zz");
                if let Ok(byte) = u8::from_str_radix(hex_pair, 16) {
                    out.push(byte);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// epay 协议值不做完整 URL 编码（go-epay 特性），但 notify_url 放 query 里需要最小转义
fn urlencoding_lite(s: &str) -> String {
    s.replace('%', "%25").replace('&', "%26").replace('=', "%3D").replace('+', "%2B")
}
