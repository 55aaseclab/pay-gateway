//! 订单存储（sqlite）。状态机：0 待支付 → 1 已支付 / 2 已关闭 / 3 异常。
//! 幂等保证：mark_paid 使用条件更新（仅 0→1 成功时返回 true，且只在成功路径触发渠道入账通知）。

use rusqlite::Connection;
use std::sync::Mutex;

pub const ST_PENDING: i64 = 0;
pub const ST_PAID: i64 = 1;
pub const ST_CLOSED: i64 = 2;
pub const ST_ABNORMAL: i64 = 3;

#[derive(Debug, Clone)]
pub struct Order {
    pub out_trade_no: String,
    pub provider: String,
    pub epay_type: String,
    pub money_cents: i64,
    pub subject: String,
    pub notify_url: String,
    pub return_url: String,
    pub status: i64,
    pub trade_no: Option<String>,
    pub paid_at: Option<i64>,
    pub created_at: i64,
    pub notified: bool,
}

pub struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    pub fn open(path: &str) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS orders (
                out_trade_no TEXT PRIMARY KEY,
                provider     TEXT NOT NULL,
                epay_type    TEXT NOT NULL,
                money_cents  INTEGER NOT NULL,
                subject      TEXT NOT NULL,
                notify_url   TEXT NOT NULL,
                return_url   TEXT NOT NULL,
                status       INTEGER NOT NULL DEFAULT 0,
                trade_no     TEXT,
                paid_at      INTEGER,
                created_at   INTEGER NOT NULL,
                notified     INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_orders_created ON orders(created_at);",
        )?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    pub fn insert(&self, o: &Order) -> Result<(), rusqlite::Error> {
        let c = self.conn.lock().unwrap();
        c.execute(
            "INSERT INTO orders (out_trade_no, provider, epay_type, money_cents, subject, notify_url, return_url, status, created_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            rusqlite::params![
                o.out_trade_no, o.provider, o.epay_type, o.money_cents, o.subject,
                o.notify_url, o.return_url, o.status, o.created_at
            ],
        )?;
        Ok(())
    }

    pub fn get(&self, out_trade_no: &str) -> Result<Option<Order>, rusqlite::Error> {
        let c = self.conn.lock().unwrap();
        let mut st = c.prepare(
            "SELECT out_trade_no, provider, epay_type, money_cents, subject, notify_url, return_url,
                    status, trade_no, paid_at, created_at, notified
             FROM orders WHERE out_trade_no = ?1",
        )?;
        let mut rows = st.query_map([out_trade_no], map_row)?;
        match rows.next() {
            Some(r) => Ok(Some(r?)),
            None => Ok(None),
        }
    }

    /// 0→1 条件更新；返回是否本次调用完成转移（幂等：重复回调/查单只会成功一次）
    pub fn mark_paid(
        &self,
        out_trade_no: &str,
        trade_no: &str,
        paid_at: i64,
    ) -> Result<bool, rusqlite::Error> {
        let c = self.conn.lock().unwrap();
        let n = c.execute(
            "UPDATE orders SET status=1, trade_no=?2, paid_at=?3
             WHERE out_trade_no=?1 AND status=0",
            rusqlite::params![out_trade_no, trade_no, paid_at],
        )?;
        Ok(n == 1)
    }

    /// 未通知 → 已通知；返回是否本次负责通知（幂等）
    pub fn claim_notify(&self, out_trade_no: &str) -> Result<bool, rusqlite::Error> {
        let c = self.conn.lock().unwrap();
        let n = c.execute(
            "UPDATE orders SET notified=1 WHERE out_trade_no=?1 AND status=1 AND notified=0",
            [out_trade_no],
        )?;
        Ok(n == 1)
    }

    pub fn set_status(&self, out_trade_no: &str, status: i64) -> Result<(), rusqlite::Error> {
        let c = self.conn.lock().unwrap();
        c.execute(
            "UPDATE orders SET status=?2 WHERE out_trade_no=?1 AND status=0",
            rusqlite::params![out_trade_no, status],
        )?;
        Ok(())
    }

    /// 超时未支付订单关闭（2 小时）
    pub fn close_expired(&self, older_than_ts: i64) -> Result<usize, rusqlite::Error> {
        let c = self.conn.lock().unwrap();
        c.execute(
            "UPDATE orders SET status=2 WHERE status=0 AND created_at < ?1",
            [older_than_ts],
        )
    }
}

fn map_row(r: &rusqlite::Row) -> Result<Order, rusqlite::Error> {
    Ok(Order {
        out_trade_no: r.get(0)?,
        provider: r.get(1)?,
        epay_type: r.get(2)?,
        money_cents: r.get(3)?,
        subject: r.get(4)?,
        notify_url: r.get(5)?,
        return_url: r.get(6)?,
        status: r.get(7)?,
        trade_no: r.get(8)?,
        paid_at: r.get(9)?,
        created_at: r.get(10)?,
        notified: r.get::<_, i64>(11)? != 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paid_is_idempotent_and_notified_once() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("t.db").to_string_lossy()).unwrap();
        let o = Order {
            out_trade_no: "NO1".into(),
            provider: "wechat".into(),
            epay_type: "wxpay".into(),
            money_cents: 1000,
            subject: "TUC10".into(),
            notify_url: "https://llm.example.com/api/user/epay/notify".into(),
            return_url: "https://llm.example.com/usage-logs".into(),
            status: ST_PENDING,
            trade_no: None,
            paid_at: None,
            created_at: 1,
            notified: false,
        };
        store.insert(&o).unwrap();
        assert!(store.mark_paid("NO1", "WX1", 42).unwrap()); // 首次成功
        assert!(!store.mark_paid("NO1", "WX1", 43).unwrap()); // 幂等：不再转移
        let got = store.get("NO1").unwrap().unwrap();
        assert_eq!(got.paid_at, Some(42)); // 金额/时间不被覆盖
        assert!(store.claim_notify("NO1").unwrap());
        assert!(!store.claim_notify("NO1").unwrap()); // 只通知一次
    }

    #[test]
    fn close_expired_only_touches_pending() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("t.db").to_string_lossy()).unwrap();
        for (no, created) in [("A", 10), ("B", 20)] {
            let o = Order {
                out_trade_no: no.into(),
                provider: "wechat".into(),
                epay_type: "wxpay".into(),
                money_cents: 100,
                subject: "s".into(),
                notify_url: "n".into(),
                return_url: "r".into(),
                status: ST_PENDING,
                trade_no: None,
                paid_at: None,
                created_at: created,
                notified: false,
            };
            store.insert(&o).unwrap();
        }
        assert_eq!(store.close_expired(15).unwrap(), 1); // 只关 A
        assert_eq!(store.get("A").unwrap().unwrap().status, ST_CLOSED);
        assert_eq!(store.get("B").unwrap().unwrap().status, ST_PENDING);
    }
}
