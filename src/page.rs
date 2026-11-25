//! 页面渲染：二维码收银台（无外部资源，全部内联）。

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

use qrcode::QrCode;

/// code_url → PNG data URI
pub fn qr_png_data_uri(text: &str) -> String {
    let code = QrCode::with_error_correction_level(text.as_bytes(), qrcode::types::EcLevel::M)
        .unwrap_or_else(|_| QrCode::new(text.as_bytes()).unwrap());
    let matrix = code
        .render::<image::Luma<u8>>()
        .quiet_zone(true)
        .module_dimensions(6, 6)
        .build();
    let dynimg = image::DynamicImage::ImageLuma8(matrix);
    let mut buf = std::io::Cursor::new(Vec::new());
    dynimg
        .write_to(&mut buf, image::ImageFormat::Png)
        .expect("png encode");
    format!("data:image/png;base64,{}", B64.encode(buf.get_ref()))
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

pub fn cashier_html_with_qr(
    out_trade_no: &str,
    subject: &str,
    money_yuan: &str,
    return_url: &str,
    code_url: &str,
) -> String {
    let qr_uri = if code_url.is_empty() {
        String::new()
    } else {
        qr_png_data_uri(code_url)
    };
    format!(
        r#"<!doctype html>
<html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>55AA 充值 · 微信扫码</title>
<style>
body{{font-family:system-ui,-apple-system,'PingFang SC','Microsoft YaHei',sans-serif;background:#f6f8fa;margin:0;
display:flex;align-items:center;justify-content:center;min-height:100vh}}
.card{{background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:32px 40px;text-align:center;max-width:360px}}
h1{{font-size:1.05rem;margin:0 0 4px;color:#111}} .money{{font-size:1.6rem;font-weight:700;color:#111;margin:4px 0 4px}}
.sub{{color:#888;font-size:.75rem;margin:0 0 12px}}
img{{width:220px;height:220px}}
.tip{{color:#555;font-size:.85rem;margin-top:12px}} .ok{{color:#0a8a3a;font-weight:700}}
</style></head><body>
<div class="card">
<h1>微信扫码支付</h1>
<div class="money">¥ {money}</div>
<div class="sub">{subject}</div>
<img src="{qr}" alt="微信支付二维码">
<div class="tip" id="tip">请使用微信扫码 · 二维码 2 小时内有效</div>
<div class="sub">订单号 {no}</div>
</div>
<script>
(function poll() {{
  fetch('/api/order/{no}').then(r=>r.json()).then(d=>{{
    if (d.status === 'paid') {{
      document.getElementById('tip').innerHTML = '<span class="ok">支付成功，正在跳转…</span>';
      setTimeout(function(){{ window.location.href = '{ret}'; }}, 1200);
      return;
    }}
    if (d.status === 'closed') {{
      document.getElementById('tip').textContent = '订单已过期，请返回钱包页重新发起';
      return;
    }}
    setTimeout(poll, 3000);
  }}).catch(function(){{ setTimeout(poll, 5000); }});
}})();
</script>
</body></html>"#,
        money = html_escape(money_yuan),
        subject = html_escape(subject),
        qr = qr_uri,
        no = html_escape(out_trade_no),
        ret = html_escape(return_url),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qr_uri_is_png_data() {
        let uri = qr_png_data_uri("weixin://wxpay/bitz");
        assert!(uri.starts_with("data:image/png;base64,"));
    }

    #[test]
    fn html_escaped() {
        let h = cashier_html_with_qr("NO1", "TUC<10>", "10.00", "https://x/?a=1&b=2", "weixin://x");
        assert!(!h.contains("TUC<10>"));
        assert!(h.contains("TUC&lt;10&gt;"));
        assert!(h.contains("a=1&amp;b=2"));
    }
}
