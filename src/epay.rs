//! 易支付协议（MD5 模式），与 go-epay（Calcium-Ion/go-epay）逐字对齐：
//! 签名 = md5_hex( sort(过滤 sign/sign_type/空值 后的 k=v，按 key 字典序，用 & 连接) + 商户Key )

use md5::{Digest, Md5};

/// 过滤参与签名的参数：去掉 sign、sign_type 和空值（对齐 go-epay ParamsFilter）
fn filter_params(params: impl IntoIterator<Item = (String, String)>) -> Vec<(String, String)> {
    params
        .into_iter()
        .filter(|(k, v)| k != "sign" && k != "sign_type" && !v.is_empty())
        .collect()
}

/// 生成待签名字符串：按 key 字典序排序，k=v 用 & 连接（对齐 go-epay CreateUrlStringWithError）
fn signing_string(mut params: Vec<(String, String)>) -> Result<String, String> {
    params.sort_by(|a, b| a.0.cmp(&b.0));
    let mut out = String::new();
    for (i, (k, v)) in params.iter().enumerate() {
        if k.is_empty() || k.contains('&') || k.contains('=') {
            return Err(format!("invalid param name: {k}"));
        }
        if v.contains('&') {
            return Err(format!("param {k} contains '&'"));
        }
        if i > 0 {
            out.push('&');
        }
        out.push_str(k);
        out.push('=');
        out.push_str(v);
    }
    Ok(out)
}

/// go-epay MD5String：md5_hex(url_string + key)
pub fn md5_sign(params: &[(String, String)], key: &str) -> Result<String, String> {
    let owned: Vec<(String, String)> = params
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let filtered = filter_params(owned);
    let s = signing_string(filtered)?;
    let mut h = Md5::new();
    h.update(s.as_bytes());
    h.update(key.as_bytes());
    Ok(hex::encode(h.finalize()))
}

/// 为一组参数附加 pid、sign、sign_type=MD5（对齐 go-epay GenerateParamsWithError）
pub fn generate_signed(
    mut params: Vec<(String, String)>,
    pid: &str,
    key: &str,
) -> Result<Vec<(String, String)>, String> {
    params.retain(|(k, _)| k != "sign" && k != "sign_type");
    params.push(("pid".into(), pid.into()));
    let sign = md5_sign(&params, key)?;
    params.push(("sign".into(), sign));
    params.push(("sign_type".into(), "MD5".into()));
    Ok(params)
}

/// 验证回调/表单参数签名（对齐 go-epay Verify 的 MD5 分支）
pub fn verify(params: &[(String, String)], key: &str) -> Result<bool, String> {
    let given = params
        .iter()
        .find(|(k, _)| k == "sign")
        .map(|(_, v)| v.clone())
        .ok_or_else(|| "missing sign".to_string())?;
    let expected = md5_sign(params, key)?;
    Ok(constant_eq(given.as_bytes(), expected.as_bytes()))
}

fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, val)| (k.to_string(), val.to_string()))
            .collect()
    }

    #[test]
    fn md5_sign_matches_reference_vector() {
        // md5_hex("a=b&c=d" + "key")，python3 -c hashlib.md5 独立验证
        let sign = md5_sign(&v(&[("c", "d"), ("a", "b")]), "key").unwrap();
        assert_eq!(sign, "ba5356d83a72bed34bee693a2f4c4db9");
    }

    #[test]
    fn filter_drops_sign_type_and_empty() {
        let sign = md5_sign(&v(&[("a", "b"), ("sign", "xx"), ("sign_type", "MD5"), ("empty", "")]), "k").unwrap();
        let expect = md5_sign(&v(&[("a", "b")]), "k").unwrap();
        assert_eq!(sign, expect);
    }

    #[test]
    fn verify_rejects_bad_sign() {
        let signed = generate_signed(v(&[("out_trade_no", "NO1"), ("money", "10.00")]), "1001", "secret").unwrap();
        assert!(verify(&signed, "secret").unwrap());
        let tampered: Vec<(String, String)> = signed
            .iter()
            .map(|(k, val)| if k == "money" { (k.clone(), "999.00".into()) } else { (k.clone(), val.clone()) })
            .collect();
        assert!(!verify(&tampered, "secret").unwrap());
    }

    #[test]
    fn rejects_ampersand_in_value() {
        assert!(md5_sign(&v(&[("name", "a&b")]), "k").is_err());
    }
}
