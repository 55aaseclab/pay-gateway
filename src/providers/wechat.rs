//! 微信支付 Native v3 模块（provider 模板）。
//!
//! 实现官方 APIv3：
//! - 请求签名：WECHATPAY2-SHA256-RSA2048（商户私钥）
//! - 回调验签：平台证书（/v3/certificates 自动拉取缓存，AES-256-GCM 解密）
//! - 回调解密：APIv3Key AES-256-GCM
//! - 下单/查单：/v3/pay/transactions/native、/v3/pay/transactions/out-trade-no/{no}
//!
//! 所有配置来自环境变量，见 .env.example。

use crate::provider::{
    Callback, CreatePayment, PayStatus, Payment, PaymentProvider, ProviderError,
};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use async_trait::async_trait;
use axum::http::{HeaderMap, HeaderValue};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use bytes::Bytes;
use rand::RngCore;
use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
use rsa::sha2::Sha256;
use rsa::signature::{SignatureEncoding, Verifier, Signer};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::RsaPrivateKey;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct WechatConfig {
    pub appid: String,
    pub mch_id: String,
    pub serial_no: String,
    /// 商户私钥 PEM（apiclient_key.pem 内容，PKCS#8）
    pub private_key_pem: String,
    pub api_v3_key: String,
    /// 默认 https://api.mch.weixin.qq.com（测试可指向 mock）
    pub api_base: String,
    /// 回调基底，如 https://pay.example.com
    pub notify_base: String,
}

pub struct WechatNativeProvider {
    cfg: WechatConfig,
    http: reqwest::Client,
    private_key: RsaPrivateKey,
    /// 平台证书缓存：serial_no → 验签公钥
    platform_keys: Arc<RwLock<HashMap<String, rsa::RsaPublicKey>>>,
}

impl WechatNativeProvider {
    pub fn new(cfg: WechatConfig) -> Result<Self, ProviderError> {
        if cfg.api_v3_key.len() != 32 {
            return Err(ProviderError::Config("APIv3Key must be 32 bytes".into()));
        }
        let private_key = RsaPrivateKey::from_pkcs8_pem(&cfg.private_key_pem)
            .or_else(|_| RsaPrivateKey::from_pkcs1_pem(&cfg.private_key_pem))
            .map_err(|e| ProviderError::Config(format!("merchant private key: {e}")))?;
        Ok(Self {
            http: reqwest::Client::new(),
            private_key,
            cfg,
            platform_keys: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    fn sign_auth_header(&self, method: &str, canonical_url: &str, body: &str) -> Result<String, ProviderError> {
        let ts = chrono::Utc::now().timestamp();
        let mut nonce = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut nonce);
        let nonce = hex::encode(nonce);
        let message = format!("{method}\n{canonical_url}\n{ts}\n{nonce}\n{body}\n");
        let key = SigningKey::<Sha256>::new(self.private_key.clone());
        let sig = key.sign(message.as_bytes());
        Ok(format!(
            "WECHATPAY2-SHA256-RSA2048 mchid=\"{}\",nonce_str=\"{}\",signature=\"{}\",timestamp=\"{}\",serial_no=\"{}\"",
            self.cfg.mch_id,
            nonce,
            B64.encode(sig.to_vec()),
            ts,
            self.cfg.serial_no
        ))
    }

    async fn api_request(
        &self,
        method: reqwest::Method,
        path_with_query: &str,
        body: &Value,
    ) -> Result<(u16, Value), ProviderError> {
        let body_str = if body.is_null() { String::new() } else { body.to_string() };
        let auth = self.sign_auth_header(
            method.as_str(),
            path_with_query,
            &body_str,
        )?;
        let url = format!("{}{}", self.cfg.api_base, path_with_query);
        let mut req = self.http.request(method, &url).header("Authorization", auth);
        if !body_str.is_empty() {
            req = req
                .header("Content-Type", "application/json")
                .header("Accept", "application/json");
        }
        let resp = req.send().await.map_err(|e| ProviderError::Upstream(e.to_string()))?;
        let status = resp.status().as_u16();
        let text = resp.text().await.map_err(|e| ProviderError::Upstream(e.to_string()))?;
        let v: Value = if text.is_empty() { Value::Null } else {
            serde_json::from_str(&text).unwrap_or(Value::Null)
        };
        Ok((status, v))
    }

    /// 平台证书：serial 未知时拉取 /v3/certificates 并缓存
    async fn ensure_platform_key(&self, serial: &str) -> Result<rsa::RsaPublicKey, ProviderError> {
        if let Some(k) = self.platform_keys.read().await.get(serial) {
            return Ok(k.clone());
        }
        let (status, v) = self
            .api_request(reqwest::Method::GET, "/v3/certificates", &Value::Null)
            .await?;
        if status != 200 {
            return Err(ProviderError::Verify(format!(
                "fetch platform certificates failed: {status}"
            )));
        }
        let items = v["data"].as_array().cloned().unwrap_or_default();
        let mut new_map: HashMap<String, rsa::RsaPublicKey> = HashMap::new();
        for item in items {
            let sn = item["serial_no"].as_str().unwrap_or("").to_string();
            let enc = &item["encrypt_certificate"];
            let cert_pem = decrypt_awc(
                &self.cfg.api_v3_key,
                enc["nonce"].as_str().unwrap_or(""),
                enc["associated_data"].as_str().unwrap_or("certificate"),
                enc["ciphertext"].as_str().unwrap_or(""),
            )?;
            let cert_pem = String::from_utf8(cert_pem)
                .map_err(|e| ProviderError::Verify(format!("cert utf8: {e}")))?;
            let pubkey = extract_public_key(&cert_pem)?;
            new_map.insert(sn, pubkey);
        }
        let mut guard = self.platform_keys.write().await;
        guard.extend(new_map);
        guard
            .get(serial)
            .cloned()
            .ok_or_else(|| ProviderError::Verify(format!("serial {serial} not found in platform certs")))
    }

    async fn verify_callback_signature(
        &self,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<(), ProviderError> {
        let hv = |name: &str| -> Result<String, ProviderError> {
            headers
                .get(name)
                .and_then(|v: &HeaderValue| v.to_str().ok())
                .map(|s| s.to_string())
                .ok_or_else(|| ProviderError::Verify(format!("missing header {name}")))
        };
        let signature = hv("Wechatpay-Signature")?;
        let ts = hv("Wechatpay-Timestamp")?;
        let nonce = hv("Wechatpay-Nonce")?;
        let serial = hv("Wechatpay-Serial")?;
        let now = chrono::Utc::now().timestamp();
        let ts_i: i64 = ts.parse().map_err(|_| ProviderError::Verify("bad timestamp".into()))?;
        if (now - ts_i).abs() > 300 {
            return Err(ProviderError::Verify("timestamp skew > 300s".into()));
        }
        let key = self.ensure_platform_key(&serial).await?;
        let message = format!("{ts}\n{nonce}\n{}\n", String::from_utf8_lossy(body));
        let sig_bytes = B64.decode(signature).map_err(|e| ProviderError::Verify(format!("sig b64: {e}")))?;
        let sig = Signature::try_from(sig_bytes.as_slice())
            .map_err(|e| ProviderError::Verify(format!("sig format: {e}")))?;
        VerifyingKey::<Sha256>::new(key)
            .verify(message.as_bytes(), &sig)
            .map_err(|_| ProviderError::Verify("signature mismatch".into()))
    }

    fn amount_cents(total: i64) -> i64 {
        total
    }
}

fn decrypt_awc(api_v3_key: &str, nonce: &str, aad: &str, ciphertext_b64: &str) -> Result<Vec<u8>, ProviderError> {
    let key_bytes = api_v3_key.as_bytes();
    let cipher = Aes256Gcm::new_from_slice(key_bytes).map_err(|e| ProviderError::Verify(format!("key: {e}")))?;
    let nonce = Nonce::from_slice(nonce.as_bytes());
    let ct = B64.decode(ciphertext_b64).map_err(|e| ProviderError::Verify(format!("ct b64: {e}")))?;
    cipher
        .decrypt(nonce, Payload { msg: &ct, aad: aad.as_bytes() })
        .map_err(|_| ProviderError::Verify("aes-gcm decrypt failed".into()))
}

fn extract_public_key(cert_pem: &str) -> Result<rsa::RsaPublicKey, ProviderError> {
    use rsa::pkcs8::DecodePublicKey;
    use x509_parser::prelude::*;
    let pem = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes())
        .map_err(|e| ProviderError::Verify(format!("cert pem: {e}")))?
        .1;
    let (_, cert) = X509Certificate::from_der(&pem.contents)
        .map_err(|e| ProviderError::Verify(format!("cert der: {e}")))?;
    let der = cert.tbs_certificate.subject_pki.raw.to_vec();
    rsa::RsaPublicKey::from_public_key_der(&der)
        .map_err(|e| ProviderError::Verify(format!("spki: {e}")))
}

#[async_trait]
impl PaymentProvider for WechatNativeProvider {
    fn epay_type(&self) -> &'static str {
        "wxpay"
    }

    fn name(&self) -> &'static str {
        "wechat"
    }

    async fn create_payment(&self, req: CreatePayment) -> Result<Payment, ProviderError> {
        if req.amount_cents <= 0 {
            return Err(ProviderError::OrderState("amount must be positive".into()));
        }
        let body = json!({
            "appid": self.cfg.appid,
            "mchid": self.cfg.mch_id,
            "description": req.subject,
            "out_trade_no": req.out_trade_no,
            "notify_url": req.notify_url,
            "amount": { "total": req.amount_cents, "currency": "CNY" },
        });
        let (status, v) = self
            .api_request(reqwest::Method::POST, "/v3/pay/transactions/native", &body)
            .await?;
        if status == 200 {
            let code_url = v["code_url"]
                .as_str()
                .ok_or_else(|| ProviderError::Upstream("missing code_url".into()))?
                .to_string();
            Ok(Payment::Qr { code_url })
        } else {
            Err(ProviderError::Upstream(format!(
                "native order failed: {status} {}",
                v["message"].as_str().unwrap_or("")
            )))
        }
    }

    async fn query_status(&self, out_trade_no: &str) -> Result<PayStatus, ProviderError> {
        let path = format!(
            "/v3/pay/transactions/out-trade-no/{}?mchid={}",
            out_trade_no, self.cfg.mch_id
        );
        let (status, v) = self.api_request(reqwest::Method::GET, &path, &Value::Null).await?;
        if status != 200 {
            if status == 404 {
                return Ok(PayStatus::Pending);
            }
            return Err(ProviderError::Upstream(format!("query failed: {status}")));
        }
        match v["trade_state"].as_str().unwrap_or("") {
            "SUCCESS" => Ok(PayStatus::Paid {
                trade_no: v["transaction_id"].as_str().unwrap_or("").to_string(),
            }),
            "CLOSED" | "REVOKED" | "PAYERROR" => Ok(PayStatus::Closed),
            _ => Ok(PayStatus::Pending),
        }
    }

    async fn handle_callback(
        &self,
        headers: &HeaderMap,
        body: &Bytes,
    ) -> Result<Callback, ProviderError> {
        self.verify_callback_signature(headers, body).await?;
        let v: Value = serde_json::from_slice(body)
            .map_err(|e| ProviderError::Verify(format!("body json: {e}")))?;
        if v["event_type"].as_str() != Some("TRANSACTION.SUCCESS") {
            return Err(ProviderError::Verify(format!(
                "unhandled event_type {}",
                v["event_type"].as_str().unwrap_or("?")
            )));
        }
        let res = &v["resource"];
        let plain = decrypt_awc(
            &self.cfg.api_v3_key,
            res["nonce"].as_str().unwrap_or(""),
            res["associated_data"].as_str().unwrap_or("transaction"),
            res["ciphertext"].as_str().unwrap_or(""),
        )?;
        let t: Value = serde_json::from_slice(&plain)
            .map_err(|e| ProviderError::Verify(format!("resource json: {e}")))?;
        let out_trade_no = t["out_trade_no"].as_str().unwrap_or("").to_string();
        if out_trade_no.is_empty() {
            return Err(ProviderError::Verify("missing out_trade_no".into()));
        }
        let trade_no = t["transaction_id"].as_str().unwrap_or("").to_string();
        let amount_cents = Self::amount_cents(t["amount"]["payer_total"].as_i64().unwrap_or(0));
        let total = Self::amount_cents(t["amount"]["total"].as_i64().unwrap_or(0));
        Ok(Callback {
            out_trade_no,
            trade_no,
            amount_cents: if amount_cents > 0 { amount_cents } else { total },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_apiv3_key_len() {
        let cfg = WechatConfig {
            appid: "wx123".into(),
            mch_id: "1900000001".into(),
            serial_no: "S1".into(),
            private_key_pem: "not-a-key".into(),
            api_v3_key: "short".into(),
            api_base: "https://api.mch.weixin.qq.com".into(),
            notify_base: "https://pay.example.com".into(),
        };
        assert!(matches!(
            WechatNativeProvider::new(cfg),
            Err(ProviderError::Config(_))
        ));
    }

    #[tokio::test]
    async fn callback_signature_bad_returns_verify_error() {
        // 生成合法 RSA 私钥；用不可达 api_base + 未知 serial 触发证书拉取失败 → Verify/Upstream 错误
        use rsa::pkcs8::EncodePrivateKey;
        let mut rng = rand::thread_rng();
        let key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let key_pem = key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap()
            .to_string();
        let cfg = WechatConfig {
            appid: "wx123".into(),
            mch_id: "1900000001".into(),
            serial_no: "S1".into(),
            private_key_pem: key_pem,
            api_v3_key: "01234567890123456789012345678901".into(),
            api_base: "http://127.0.0.1:1".into(), // 不可达 → 证书拉取失败
            notify_base: "https://pay.example.com".into(),
        };
        let p = WechatNativeProvider::new(cfg).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("Wechatpay-Signature", HeaderValue::from_static("abc"));
        headers.insert("Wechatpay-Timestamp", HeaderValue::from_static("1"));
        headers.insert("Wechatpay-Nonce", HeaderValue::from_static("n"));
        headers.insert("Wechatpay-Serial", HeaderValue::from_static("UNKNOWN"));
        let r = p.handle_callback(&headers, &Bytes::from("{}")).await;
        assert!(matches!(r, Err(ProviderError::Verify(_)) | Err(ProviderError::Upstream(_))));
    }
}
