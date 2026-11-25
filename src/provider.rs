//! 支付 provider 抽象。新增渠道 = 实现本 trait + 在 providers::registry 注册，
//! epay 协议层、订单层、页面层全部复用。

use async_trait::async_trait;
use axum::http::HeaderMap;
use bytes::Bytes;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct CreatePayment {
    pub out_trade_no: String,
    /// 人民币分
    pub amount_cents: i64,
    pub subject: String,
    /// 微信支付回调地址（网关公网基底 + /notify/{provider}）
    pub notify_url: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Payment {
    /// 扫码支付：上游返回 code_url，网关渲染二维码
    Qr { code_url: String },
    /// 跳转支付（预留：支付宝 wap / stripe checkout）
    Redirect { url: String },
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PayStatus {
    Pending,
    /// 已支付；trade_no 为渠道流水号
    Paid { trade_no: String },
    Closed,
}

#[derive(Debug, Clone)]
pub struct Callback {
    pub out_trade_no: String,
    pub trade_no: String,
    /// 渠道侧金额（分），网关用于与订单金额比对
    pub amount_cents: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    #[error("upstream error: {0}")]
    Upstream(String),
    #[error("config error: {0}")]
    Config(String),
    #[error("verify failed: {0}")]
    Verify(String),
    #[error("order not found or closed: {0}")]
    OrderState(String),
}

/// 渠道模块接口。实现必须是无共享可变状态（&self），并发安全。
#[async_trait]
pub trait PaymentProvider: Send + Sync {
    /// epay submit 的 type 参数（new-api PayMethods 配置值），如 "wxpay"
    fn epay_type(&self) -> &'static str;
    /// 渠道名（URL 路径段），如 "wechat"
    fn name(&self) -> &'static str;
    /// 发起支付
    async fn create_payment(&self, req: CreatePayment) -> Result<Payment, ProviderError>;
    /// 主动查单（回调丢失兜底）
    async fn query_status(&self, out_trade_no: &str) -> Result<PayStatus, ProviderError>;
    /// 渠道回调处理：验签 + 解密，返回业务结果。实现方自行幂等（网关层再做订单幂等）
    async fn handle_callback(
        &self,
        headers: &HeaderMap,
        body: &Bytes,
    ) -> Result<Callback, ProviderError>;
}

#[derive(Default)]
pub struct Registry {
    providers: Vec<Box<dyn PaymentProvider>>,
}

impl Registry {
    pub fn register(&mut self, p: Box<dyn PaymentProvider>) {
        self.providers.push(p);
    }

    /// 按 epay type 定位（submit 时）
    pub fn by_epay_type(&self, epay_type: &str) -> Option<&dyn PaymentProvider> {
        self.providers
            .iter()
            .map(|b| b.as_ref())
            .find(|p| p.epay_type() == epay_type)
    }

    /// 按渠道名定位（回调路由 /notify/{name} 时）
    pub fn by_name(&self, name: &str) -> Option<&dyn PaymentProvider> {
        self.providers
            .iter()
            .map(|b| b.as_ref())
            .find(|p| p.name() == name)
    }

    pub fn list(&self) -> Vec<&'static str> {
        self.providers.iter().map(|b| b.name()).collect()
    }
}
