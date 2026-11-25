# pay-gateway

55AA 易支付协议网关（Rust）：对 new-api 暴露易支付 MD5 协议，后端接可插拔支付渠道。

## 架构

```
new-api ──epay(MD5)──▶ pay-gateway ──provider trait──▶ wechat(Native v3) / 未来的 alipay、stripe…
```

- **协议层** `src/epay.rs`：MD5 签名/验签，与 go-epay 逐字对齐（过滤 sign/sign_type/空值 → key 字典序 → `md5_hex(k=v&…+key)`）
- **渠道层** `src/provider.rs`：`PaymentProvider` trait（`create_payment / query_status / handle_callback`）+ 注册表
- **渠道实现** `src/providers/`：`wechat.rs`（微信 Native v3：请求签名、平台证书验签、APIv3 AES-256-GCM 回调解密）——**新渠道照此文件做模板**
- **订单层** `src/orders.rs`：sqlite（WAL），状态机 0待支付/1已支付/2已关闭/3异常；mark_paid 条件更新幂等；notified 只通知一次
- **页面层** `src/page.rs`：二维码收银台（内联 PNG，3s 轮询，成功跳 return_url，2h 过期）

## 新增一个支付渠道

1. `src/providers/` 新建模块，实现 `PaymentProvider` 四个方法
2. `src/providers/mod.rs::build_registry` 注册一行
3. 单测覆盖：回调验签失败路径 + 金额字段解析
无需动 epay/订单/页面任何代码。

## 本地开发

```bash
cargo build && cargo test
BIND_HOST=127.0.0.1:8787 DB_PATH=/tmp/o.db \
EPAY_PID=1001 EPAY_KEY=test NOTIFY_BASE=http://127.0.0.1:8787 \
WXPAY_APPID=x WXPAY_MCH_ID=x WXPAY_SERIAL_NO=x WXPAY_PRIVATE_KEY=x WXPAY_APIV3_KEY=$(python3 -c 'print("k"*32)') \
cargo run
curl -s localhost:8787/healthz
```

## 部署（pay.55aaseclab.com）

1. DNS A 记录 pay → 165.154.203.40
2. 服务器 `/opt/epay-deploy/`：`docker-compose.yml` + `.env`（cp .env.example，填真实商户凭据，chmod 600）
3. nginx server 块：TLS（复用通配符证书）→ 反代 127.0.0.1:8787
4. new-api 后台支付设置：`PayAddress=https://pay.55aaseclab.com`，EpayId/EpayKey 与 .env 一致
5. 验证：0.01 元真实下单 → 扫码 → 回调入账 → 钱包余额 + 订单表

## 设计红线

- 验签失败：拒绝 + warn 日志（PRD 3.1.7）
- 金额不一致：拒入账、订单标异常、人工介入
- 幂等：回调重复/查单兜底/并发通知，mark_paid 条件更新只放行一次
- 回调丢失：收银台轮询主动查单（5s×N 由前端轮询节奏决定）+ 后台每分钟关单（2h）
- 凭据只在 `/opt/epay-deploy/.env`，不入 git
