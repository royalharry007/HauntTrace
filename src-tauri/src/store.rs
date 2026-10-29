//! Local evidence store (SQLite). Everything stays on this computer.
//! Only alerts, investigations, their evidence and user actions are written;
//! raw process samples are kept in memory and never persisted.

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::settings::Settings;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRecord {
    pub id: String,
    pub created_ms: u64,
    pub rule: String,
    pub rule_label: String,
    pub priority: String,
    pub pid: u32,
    /// Process creation FILETIME as a string (exceeds JS number precision).
    pub process_created: String,
    pub process_name: String,
    pub exe_path: Option<String>,
    pub reason: String,
    pub metrics: Value,
    pub details: Value,
    pub delivery: Value,
    pub status: String,
    pub investigation_id: Option<String>,
    pub synthetic: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationRecord {
    pub id: String,
    pub alert_id: String,
    pub started_ms: u64,
    pub finished_ms: Option<u64>,
    /// running | completed | cancelled | failed
    pub status: String,
    pub model: String,
    /// True when the report was produced without the model (model unavailable).
    pub deterministic: bool,
    pub report: Option<Value>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepRecord {
    pub seq: u32,
    pub created_ms: u64,
    /// packet | thinking | plan | tool | tool_rejected | report | note | error
    pub kind: String,
    pub title: String,
    pub payload: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRecord {
    pub evidence_id: String,
    pub created_ms: u64,
    pub source: String,
    pub title: String,
    pub summary: String,
    pub data: Value,
    pub synthetic: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionRecord {
    pub created_ms: u64,
    pub alert_id: Option<String>,
    pub investigation_id: Option<String>,
    pub action: String,
    pub detail: String,
    pub outcome: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct InvestigationDetail {
    pub investigation: InvestigationRecord,
    pub alert: Option<AlertRecord>,
    pub steps: Vec<StepRecord>,
    pub evidence: Vec<EvidenceRecord>,
    pub actions: Vec<ActionRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StoreStats {
    pub alerts: u64,
    pub investigations: u64,
    pub evidence: u64,
    pub db_bytes: u64,
}

pub struct Store {
    conn: Connection,
    path: Option<std::path::PathBuf>,
}

fn sql_err(e: rusqlite::Error) -> String {
    format!("database error: {e}")
}

fn jv(s: Option<String>) -> Value {
    s.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(Value::Null)
}

impl Store {
    pub fn open(path: &std::path::Path) -> Result<Self, String> {
        let conn = Connection::open(path).map_err(sql_err)?;
        let s = Self { conn, path: Some(path.to_path_buf()) };
        s.migrate()?;
        Ok(s)
    }

    pub fn open_in_memory() -> Result<Self, String> {
        let s = Self { conn: Connection::open_in_memory().map_err(sql_err)?, path: None };
        s.migrate()?;
        Ok(s)
    }

    fn migrate(&self) -> Result<(), String> {
        self.conn
            .execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA synchronous=NORMAL;
                 PRAGMA foreign_keys=ON;
                 CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY, created_ms INTEGER NOT NULL, rule TEXT NOT NULL, rule_label TEXT NOT NULL,
                    priority TEXT NOT NULL, pid INTEGER NOT NULL, process_created TEXT NOT NULL, process_name TEXT NOT NULL,
                    exe_path TEXT, reason TEXT NOT NULL, metrics TEXT, details TEXT, delivery TEXT,
                    status TEXT NOT NULL, investigation_id TEXT, synthetic INTEGER NOT NULL DEFAULT 0);
                 CREATE INDEX IF NOT EXISTS alerts_created ON alerts(created_ms);
                 CREATE TABLE IF NOT EXISTS investigations (
                    id TEXT PRIMARY KEY, alert_id TEXT NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
                    started_ms INTEGER NOT NULL, finished_ms INTEGER, status TEXT NOT NULL, model TEXT NOT NULL,
                    deterministic INTEGER NOT NULL DEFAULT 0, report TEXT, error TEXT);
                 CREATE TABLE IF NOT EXISTS steps (
                    investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
                    seq INTEGER NOT NULL, created_ms INTEGER NOT NULL, kind TEXT NOT NULL, title TEXT NOT NULL, payload TEXT,
                    PRIMARY KEY (investigation_id, seq));
                 CREATE TABLE IF NOT EXISTS evidence (
                    investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
                    evidence_id TEXT NOT NULL, created_ms INTEGER NOT NULL, source TEXT NOT NULL, title TEXT NOT NULL,
                    summary TEXT NOT NULL, data TEXT, synthetic INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (investigation_id, evidence_id));
                 CREATE TABLE IF NOT EXISTS actions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, created_ms INTEGER NOT NULL,
                    alert_id TEXT REFERENCES alerts(id) ON DELETE CASCADE, investigation_id TEXT,
                    action TEXT NOT NULL, detail TEXT NOT NULL, outcome TEXT NOT NULL);",
            )
            .map_err(sql_err)
    }

    // ---- settings ----

    pub fn load_settings(&self) -> Option<Settings> {
        let v: Option<String> = self.conn.query_row("SELECT value FROM settings WHERE key='settings'", [], |r| r.get(0)).optional().ok()?;
        v.and_then(|s| serde_json::from_str(&s).ok())
    }

    pub fn save_settings(&self, s: &Settings) -> Result<(), String> {
        let v = serde_json::to_string(s).map_err(|e| e.to_string())?;
        self.conn.execute("INSERT INTO settings(key,value) VALUES('settings',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value", params![v]).map_err(sql_err)?;
        Ok(())
    }

    pub fn get_kv(&self, key: &str) -> Option<String> {
        self.conn.query_row("SELECT value FROM settings WHERE key=?1", params![key], |r| r.get(0)).optional().ok().flatten()
    }

    pub fn set_kv(&self, key: &str, value: &str) -> Result<(), String> {
        self.conn.execute("INSERT INTO settings(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value", params![key, value]).map_err(sql_err)?;
        Ok(())
    }

    // ---- alerts ----

    pub fn insert_alert(&self, a: &AlertRecord) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO alerts(id,created_ms,rule,rule_label,priority,pid,process_created,process_name,exe_path,reason,metrics,details,delivery,status,investigation_id,synthetic)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)",
                params![
                    a.id, a.created_ms as i64, a.rule, a.rule_label, a.priority, a.pid, a.process_created, a.process_name, a.exe_path, a.reason,
                    a.metrics.to_string(), a.details.to_string(), a.delivery.to_string(), a.status, a.investigation_id, a.synthetic as i32
                ],
            )
            .map_err(sql_err)?;
        Ok(())
    }

    fn row_alert(r: &rusqlite::Row) -> rusqlite::Result<AlertRecord> {
        Ok(AlertRecord {
            id: r.get(0)?,
            created_ms: r.get::<_, i64>(1)? as u64,
            rule: r.get(2)?,
            rule_label: r.get(3)?,
            priority: r.get(4)?,
            pid: r.get(5)?,
            process_created: r.get(6)?,
            process_name: r.get(7)?,
            exe_path: r.get(8)?,
            reason: r.get(9)?,
            metrics: jv(r.get(10)?),
            details: jv(r.get(11)?),
            delivery: jv(r.get(12)?),
            status: r.get(13)?,
            investigation_id: r.get(14)?,
            synthetic: r.get::<_, i32>(15)? != 0,
        })
    }

    const ALERT_COLS: &'static str =
        "id,created_ms,rule,rule_label,priority,pid,process_created,process_name,exe_path,reason,metrics,details,delivery,status,investigation_id,synthetic";

    pub fn list_alerts(&self, limit: u32) -> Result<Vec<AlertRecord>, String> {
        let mut st = self.conn.prepare(&format!("SELECT {} FROM alerts ORDER BY created_ms DESC LIMIT ?1", Self::ALERT_COLS)).map_err(sql_err)?;
        let rows = st.query_map(params![limit], Self::row_alert).map_err(sql_err)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(sql_err)
    }

    pub fn get_alert(&self, id: &str) -> Result<Option<AlertRecord>, String> {
        self.conn
            .query_row(&format!("SELECT {} FROM alerts WHERE id=?1", Self::ALERT_COLS), params![id], Self::row_alert)
            .optional()
            .map_err(sql_err)
    }

    pub fn set_alert_status(&self, id: &str, status: &str, investigation_id: Option<&str>) -> Result<(), String> {
        self.conn
            .execute("UPDATE alerts SET status=?2, investigation_id=COALESCE(?3, investigation_id) WHERE id=?1", params![id, status, investigation_id])
            .map_err(sql_err)?;
        Ok(())
    }

    pub fn delete_alert(&self, id: &str) -> Result<(), String> {
        self.conn.execute("DELETE FROM alerts WHERE id=?1", params![id]).map_err(sql_err)?;
        Ok(())
    }

    // ---- investigations ----

    pub fn insert_investigation(&self, i: &InvestigationRecord) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO investigations(id,alert_id,started_ms,finished_ms,status,model,deterministic,report,error) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![
                    i.id, i.alert_id, i.started_ms as i64, i.finished_ms.map(|v| v as i64), i.status, i.model, i.deterministic as i32,
                    i.report.as_ref().map(|r| r.to_string()), i.error
                ],
            )
            .map_err(sql_err)?;
        Ok(())
    }

    pub fn finish_investigation(&self, id: &str, status: &str, finished_ms: u64, deterministic: bool, report: Option<&Value>, error: Option<&str>) -> Result<(), String> {
        self.conn
            .execute(
                "UPDATE investigations SET status=?2, finished_ms=?3, deterministic=?4, report=?5, error=?6 WHERE id=?1",
                params![id, status, finished_ms as i64, deterministic as i32, report.map(|r| r.to_string()), error],
            )
            .map_err(sql_err)?;
        Ok(())
    }

    pub fn append_step(&self, inv: &str, s: &StepRecord) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO steps(investigation_id,seq,created_ms,kind,title,payload) VALUES(?1,?2,?3,?4,?5,?6)",
                params![inv, s.seq, s.created_ms as i64, s.kind, s.title, s.payload.to_string()],
            )
            .map_err(sql_err)?;
        Ok(())
    }

    pub fn insert_evidence(&self, inv: &str, e: &EvidenceRecord) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO evidence(investigation_id,evidence_id,created_ms,source,title,summary,data,synthetic) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                params![inv, e.evidence_id, e.created_ms as i64, e.source, e.title, e.summary, e.data.to_string(), e.synthetic as i32],
            )
            .map_err(sql_err)?;
        Ok(())
    }

    pub fn record_action(&self, a: &ActionRecord) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO actions(created_ms,alert_id,investigation_id,action,detail,outcome) VALUES(?1,?2,?3,?4,?5,?6)",
                params![a.created_ms as i64, a.alert_id, a.investigation_id, a.action, a.detail, a.outcome],
            )
            .map_err(sql_err)?;
        Ok(())
    }

    fn row_inv(r: &rusqlite::Row) -> rusqlite::Result<InvestigationRecord> {
        Ok(InvestigationRecord {
            id: r.get(0)?,
            alert_id: r.get(1)?,
            started_ms: r.get::<_, i64>(2)? as u64,
            finished_ms: r.get::<_, Option<i64>>(3)?.map(|v| v as u64),
            status: r.get(4)?,
            model: r.get(5)?,
            deterministic: r.get::<_, i32>(6)? != 0,
            report: Some(jv(r.get(7)?)).filter(|v| !v.is_null()),
            error: r.get(8)?,
        })
    }

    pub fn list_investigations(&self, limit: u32) -> Result<Vec<InvestigationRecord>, String> {
        let mut st = self
            .conn
            .prepare("SELECT id,alert_id,started_ms,finished_ms,status,model,deterministic,report,error FROM investigations ORDER BY started_ms DESC LIMIT ?1")
            .map_err(sql_err)?;
        let rows = st.query_map(params![limit], Self::row_inv).map_err(sql_err)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(sql_err)
    }

    pub fn get_investigation(&self, id: &str) -> Result<Option<InvestigationDetail>, String> {
        let inv = self
            .conn
            .query_row("SELECT id,alert_id,started_ms,finished_ms,status,model,deterministic,report,error FROM investigations WHERE id=?1", params![id], Self::row_inv)
            .optional()
            .map_err(sql_err)?;
        let Some(investigation) = inv else { return Ok(None) };
        let alert = self.get_alert(&investigation.alert_id)?;
        let mut st = self.conn.prepare("SELECT seq,created_ms,kind,title,payload FROM steps WHERE investigation_id=?1 ORDER BY seq").map_err(sql_err)?;
        let steps = st
            .query_map(params![id], |r| {
                Ok(StepRecord { seq: r.get(0)?, created_ms: r.get::<_, i64>(1)? as u64, kind: r.get(2)?, title: r.get(3)?, payload: jv(r.get(4)?) })
            })
            .map_err(sql_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sql_err)?;
        let mut st = self
            .conn
            .prepare("SELECT evidence_id,created_ms,source,title,summary,data,synthetic FROM evidence WHERE investigation_id=?1 ORDER BY created_ms, rowid")
            .map_err(sql_err)?;
        let evidence = st
            .query_map(params![id], |r| {
                Ok(EvidenceRecord {
                    evidence_id: r.get(0)?,
                    created_ms: r.get::<_, i64>(1)? as u64,
                    source: r.get(2)?,
                    title: r.get(3)?,
                    summary: r.get(4)?,
                    data: jv(r.get(5)?),
                    synthetic: r.get::<_, i32>(6)? != 0,
                })
            })
            .map_err(sql_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sql_err)?;
        let actions = self.actions_for(&investigation.alert_id)?;
        Ok(Some(InvestigationDetail { investigation, alert, steps, evidence, actions }))
    }

    pub fn actions_for(&self, alert_id: &str) -> Result<Vec<ActionRecord>, String> {
        let mut st = self
            .conn
            .prepare("SELECT created_ms,alert_id,investigation_id,action,detail,outcome FROM actions WHERE alert_id=?1 ORDER BY created_ms")
            .map_err(sql_err)?;
        let rows = st
            .query_map(params![alert_id], |r| {
                Ok(ActionRecord {
                    created_ms: r.get::<_, i64>(0)? as u64,
                    alert_id: r.get(1)?,
                    investigation_id: r.get(2)?,
                    action: r.get(3)?,
                    detail: r.get(4)?,
                    outcome: r.get(5)?,
                })
            })
            .map_err(sql_err)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(sql_err)
    }

    /// Mark investigations left "running" by a previous crash/exit as failed.
    pub fn recover_interrupted(&self, now: u64) -> Result<(), String> {
        self.conn
            .execute("UPDATE investigations SET status='failed', finished_ms=?1, error='Interrupted: HauntTrace closed during the investigation' WHERE status='running'", params![now as i64])
            .map_err(sql_err)?;
        self.conn.execute("UPDATE alerts SET status='new' WHERE status='investigating'", []).map_err(sql_err)?;
        Ok(())
    }

    /// Enforce retention: drop alerts (and their investigations) older than
    /// `retention_days`, and keep at most `max_alerts`.
    pub fn prune(&self, now: u64, retention_days: u32, max_alerts: u32) -> Result<usize, String> {
        let cutoff = now.saturating_sub(retention_days as u64 * 86_400_000) as i64;
        let mut n = self.conn.execute("DELETE FROM alerts WHERE created_ms < ?1", params![cutoff]).map_err(sql_err)?;
        n += self
            .conn
            .execute("DELETE FROM alerts WHERE id NOT IN (SELECT id FROM alerts ORDER BY created_ms DESC LIMIT ?1)", params![max_alerts])
            .map_err(sql_err)?;
        Ok(n)
    }

    pub fn delete_all_history(&self) -> Result<(), String> {
        self.conn.execute_batch("DELETE FROM actions; DELETE FROM evidence; DELETE FROM steps; DELETE FROM investigations; DELETE FROM alerts; VACUUM;").map_err(sql_err)
    }

    pub fn stats(&self) -> StoreStats {
        let c = |sql: &str| self.conn.query_row(sql, [], |r| r.get::<_, i64>(0)).unwrap_or(0) as u64;
        StoreStats {
            alerts: c("SELECT COUNT(*) FROM alerts"),
            investigations: c("SELECT COUNT(*) FROM investigations"),
            evidence: c("SELECT COUNT(*) FROM evidence"),
            db_bytes: self.path.as_ref().and_then(|p| std::fs::metadata(p).ok()).map(|m| m.len()).unwrap_or(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alert(id: &str, t: u64) -> AlertRecord {
        AlertRecord {
            id: id.into(),
            created_ms: t,
            rule: "sustained_cpu".into(),
            rule_label: "Sustained CPU activity".into(),
            priority: "warning".into(),
            pid: 42,
            process_created: "133000000000000000".into(),
            process_name: "x.exe".into(),
            exe_path: None,
            reason: "r".into(),
            metrics: serde_json::json!({"cpu_avg": 30.0}),
            details: Value::Null,
            delivery: Value::Null,
            status: "new".into(),
            investigation_id: None,
            synthetic: true,
        }
    }

    #[test]
    fn roundtrip_and_cascade_delete() {
        let s = Store::open_in_memory().unwrap();
        s.insert_alert(&alert("a1", 1000)).unwrap();
        let inv = InvestigationRecord {
            id: "i1".into(),
            alert_id: "a1".into(),
            started_ms: 1,
            finished_ms: None,
            status: "running".into(),
            model: "m".into(),
            deterministic: false,
            report: None,
            error: None,
        };
        s.insert_investigation(&inv).unwrap();
        s.append_step("i1", &StepRecord { seq: 0, created_ms: 1, kind: "packet".into(), title: "t".into(), payload: Value::Null }).unwrap();
        s.insert_evidence("i1", &EvidenceRecord { evidence_id: "E1".into(), created_ms: 1, source: "detector".into(), title: "t".into(), summary: "s".into(), data: Value::Null, synthetic: true }).unwrap();
        s.finish_investigation("i1", "completed", 5, false, Some(&serde_json::json!({"finding": "f"})), None).unwrap();
        let d = s.get_investigation("i1").unwrap().unwrap();
        assert_eq!(d.steps.len(), 1);
        assert_eq!(d.evidence.len(), 1);
        assert_eq!(d.investigation.report.unwrap()["finding"], "f");
        assert_eq!(d.alert.unwrap().process_created, "133000000000000000");
        s.delete_alert("a1").unwrap();
        assert!(s.get_investigation("i1").unwrap().is_none());
    }

    #[test]
    fn prune_enforces_retention_and_cap() {
        let s = Store::open_in_memory().unwrap();
        let day = 86_400_000u64;
        for i in 0..10u64 {
            s.insert_alert(&alert(&format!("a{i}"), 100 * day + i)).unwrap();
        }
        s.insert_alert(&alert("old", 10 * day)).unwrap();
        s.prune(100 * day + 100, 30, 5).unwrap();
        let left = s.list_alerts(100).unwrap();
        assert_eq!(left.len(), 5);
        assert!(left.iter().all(|a| a.id != "old"));
    }

    #[test]
    fn settings_roundtrip() {
        let s = Store::open_in_memory().unwrap();
        assert!(s.load_settings().is_none());
        let mut st = Settings::default();
        st.alerts.volume = 12;
        s.save_settings(&st).unwrap();
        assert_eq!(s.load_settings().unwrap().alerts.volume, 12);
    }
}
