//! SQLite database backend. A queryable relational mirror of the engagement,
//! written to <root>/engagement.db alongside the JSON state. This gives the
//! framework a real database (for querying, reporting, and scale) without
//! risking the JSON as the source of truth — the DB is rebuilt from state.

use crate::model::state::Engagement;
use anyhow::Result;
use rusqlite::Connection;
use std::path::Path;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS hosts (
    ip TEXT PRIMARY KEY, hostnames TEXT, os TEXT, reach TEXT,
    compromised INTEGER, open_ports INTEGER
);
CREATE TABLE IF NOT EXISTS services (
    ip TEXT, port INTEGER, proto TEXT, name TEXT, product TEXT, version TEXT,
    PRIMARY KEY (ip, port, proto)
);
CREATE TABLE IF NOT EXISTS credentials (
    user TEXT, domain TEXT, secret TEXT, kind TEXT, source TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    severity TEXT, title TEXT, location TEXT, source TEXT, cve TEXT
);
CREATE TABLE IF NOT EXISTS loot (
    kind TEXT, name TEXT, path TEXT, host TEXT, source TEXT, size INTEGER, ts TEXT
);
CREATE TABLE IF NOT EXISTS records (
    id INTEGER PRIMARY KEY, phase TEXT, tool TEXT, target TEXT, command TEXT,
    exit_code INTEGER, output_path TEXT, started TEXT
);
"#;

/// Rebuild the SQLite database from the current engagement state.
pub fn sync(eng: &Engagement, root: &Path) -> Result<()> {
    let path = root.join("engagement.db");
    let conn = Connection::open(&path)?;
    conn.execute_batch(SCHEMA)?;
    let tx = conn.unchecked_transaction()?;
    tx.execute_batch(
        "DELETE FROM hosts; DELETE FROM services; DELETE FROM credentials;
         DELETE FROM findings; DELETE FROM loot; DELETE FROM records;",
    )?;

    for h in eng.hosts.values() {
        tx.execute(
            "INSERT INTO hosts (ip,hostnames,os,reach,compromised,open_ports) VALUES (?1,?2,?3,?4,?5,?6)",
            rusqlite::params![
                h.ip,
                h.hostnames.join(","),
                h.os.clone().unwrap_or_default(),
                format!("{:?}", h.reach),
                h.compromised as i64,
                h.open().count() as i64,
            ],
        )?;
        for s in h.open() {
            tx.execute(
                "INSERT OR REPLACE INTO services (ip,port,proto,name,product,version) VALUES (?1,?2,?3,?4,?5,?6)",
                rusqlite::params![h.ip, s.port as i64, s.proto, s.name, s.product, s.version],
            )?;
        }
    }
    for c in &eng.creds {
        tx.execute(
            "INSERT INTO credentials (user,domain,secret,kind,source) VALUES (?1,?2,?3,?4,?5)",
            rusqlite::params![
                c.user,
                c.domain.clone().unwrap_or_default(),
                c.secret,
                c.kind.label(),
                c.source
            ],
        )?;
    }
    for f in &eng.findings {
        tx.execute(
            "INSERT INTO findings (severity,title,location,source,cve) VALUES (?1,?2,?3,?4,?5)",
            rusqlite::params![
                f.severity.label(),
                f.title,
                f.location.clone().unwrap_or_default(),
                f.source,
                f.cve.join(",")
            ],
        )?;
    }
    for l in &eng.loot {
        tx.execute(
            "INSERT INTO loot (kind,name,path,host,source,size,ts) VALUES (?1,?2,?3,?4,?5,?6,?7)",
            rusqlite::params![
                l.kind.label(),
                l.name,
                l.path,
                l.host.clone().unwrap_or_default(),
                l.source,
                l.size.map(|n| n as i64),
                l.ts
            ],
        )?;
    }
    for r in &eng.records {
        tx.execute(
            "INSERT OR REPLACE INTO records (id,phase,tool,target,command,exit_code,output_path,started) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            rusqlite::params![r.id as i64, r.phase.slug(), r.tool, r.target.clone().unwrap_or_default(), r.command, r.exit_code, r.output_path, r.started],
        )?;
    }
    tx.commit()?;
    Ok(())
}

/// Run a read-only SQL query and return rows as text (for /sql).
pub fn query(root: &Path, sql: &str) -> Result<Vec<Vec<String>>> {
    let path = root.join("engagement.db");
    let conn = Connection::open(&path)?;
    let mut stmt = conn.prepare(sql)?;
    let ncols = stmt.column_count();
    let mut out = vec![];
    // header row
    out.push(
        (0..ncols)
            .map(|i| stmt.column_name(i).unwrap_or("?").to_string())
            .collect(),
    );
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let mut r = vec![];
        for i in 0..ncols {
            let v: rusqlite::types::Value = row.get(i)?;
            r.push(match v {
                rusqlite::types::Value::Null => String::new(),
                rusqlite::types::Value::Integer(n) => n.to_string(),
                rusqlite::types::Value::Real(f) => f.to_string(),
                rusqlite::types::Value::Text(t) => t,
                rusqlite::types::Value::Blob(_) => "<blob>".into(),
            });
        }
        out.push(r);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::state::Engagement;
    use crate::model::{Credential, SecretKind};

    #[test]
    fn sync_and_query() {
        let dir = std::env::temp_dir().join(format!("shrike-db-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut eng = Engagement::new("t");
        eng.add_cred(Credential::new("admin", "pw", SecretKind::Password, "test"));
        sync(&eng, &dir).unwrap();
        let rows = query(&dir, "SELECT user, kind FROM credentials").unwrap();
        assert_eq!(rows.len(), 2); // header + 1 row
        assert_eq!(rows[1][0], "admin");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
