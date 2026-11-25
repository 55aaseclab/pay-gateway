pub mod wechat;

use crate::provider::Registry;

/// 组装 provider 注册表。新增渠道：实现 PaymentProvider 后在此注册一行。
pub fn build_registry(wechat_cfg: wechat::WechatConfig) -> Result<Registry, String> {
    let mut reg = Registry::default();
    let wechat = wechat::WechatNativeProvider::new(wechat_cfg)
        .map_err(|e| format!("wechat provider init: {e}"))?;
    reg.register(Box::new(wechat));
    Ok(reg)
}
