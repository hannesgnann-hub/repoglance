use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};

use crate::models::{
    Issue, IssueCategory, IssuePath, IssueSeverity, NewScan, RepositoryDetails, RepositoryOverview,
    ScanSummary, ScoreLevel, ScorePenalty,
};

pub struct Storage {
    db_path: PathBuf,
}

impl Storage {
    pub fn new(db_path: impl Into<PathBuf>) -> Result<Self> {
        let db_path = db_path.into();
        if let Some(parent) = db_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let storage = Self { db_path };
        storage.initialize()?;
        Ok(storage)
    }

    pub fn add_repository(&self, path: &Path) -> Result<RepositoryOverview> {
        if !path.join(".git").exists() {
            return Err(anyhow!(
                "This folder does not appear to be a Git repository."
            ));
        }

        let canonical = path
            .canonicalize()
            .context("Repository path could not be resolved.")?;
        let name = canonical
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("Repository")
            .to_string();
        let now = Utc::now().to_rfc3339();
        let conn = self.connection()?;
        let existing = conn
            .query_row(
                "SELECT id FROM repositories WHERE path = ?1",
                params![canonical.to_string_lossy().to_string()],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;

        let id = if let Some(id) = existing {
            id
        } else {
            conn.execute(
                "INSERT INTO repositories (name, path, added_at, last_scan_at) VALUES (?1, ?2, ?3, NULL)",
                params![name, canonical.to_string_lossy().to_string(), now],
            )?;
            conn.last_insert_rowid()
        };

        self.repository(id)
    }

    pub fn remove_repository(&self, id: i64) -> Result<()> {
        let conn = self.connection()?;
        conn.execute("DELETE FROM repositories WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn repositories(&self) -> Result<Vec<RepositoryOverview>> {
        let conn = self.connection()?;
        let mut stmt = conn.prepare(
            "SELECT id, name, path, added_at, last_scan_at FROM repositories ORDER BY name COLLATE NOCASE",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(RepositoryOverview {
                id: row.get(0)?,
                name: row.get(1)?,
                path: row.get(2)?,
                added_at: row.get(3)?,
                last_scan_at: row.get(4)?,
                missing: false,
                latest_scan: None,
            })
        })?;

        let mut repositories = Vec::new();
        for row in rows {
            let mut repository = row?;
            repository.missing = !Path::new(&repository.path).exists();
            repository.latest_scan = self.latest_scan(repository.id)?;
            repositories.push(repository);
        }
        Ok(repositories)
    }

    pub fn repository(&self, id: i64) -> Result<RepositoryOverview> {
        self.repositories()?
            .into_iter()
            .find(|repository| repository.id == id)
            .ok_or_else(|| anyhow!("Repository not found."))
    }

    pub fn details(&self, id: i64) -> Result<RepositoryDetails> {
        let repository = self.repository(id)?;
        let latest_scan = self.latest_scan(id)?;
        let issues = if let Some(scan) = &latest_scan {
            self.issues(scan.id)?
        } else {
            Vec::new()
        };
        let history = self.scan_history(id)?;

        Ok(RepositoryDetails {
            repository,
            latest_scan,
            issues,
            history,
        })
    }

    pub fn save_scan(&self, scan: NewScan) -> Result<RepositoryDetails> {
        let mut conn = self.connection()?;
        let transaction = conn.transaction()?;
        let breakdown_json = serde_json::to_string(&scan.score_breakdown)?;
        transaction.execute(
            "INSERT INTO scans (
                repository_id, created_at, score, score_level, working_tree_size, git_size,
                total_size, potential_cleanup, security_score, issue_count, score_breakdown
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                scan.repository_id,
                scan.created_at,
                scan.score,
                score_level_to_str(scan.score_level),
                scan.working_tree_size as i64,
                scan.git_size as i64,
                scan.total_size as i64,
                scan.potential_cleanup as i64,
                scan.security_score,
                scan.issue_count,
                breakdown_json,
            ],
        )?;
        let scan_id = transaction.last_insert_rowid();

        for issue in scan.issues {
            transaction.execute(
                "INSERT INTO issues (
                    scan_id, category, severity, title, description, estimated_cleanup, detected_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    scan_id,
                    issue.category.as_str(),
                    issue.severity.as_str(),
                    issue.title,
                    issue.description,
                    issue.estimated_cleanup_bytes as i64,
                    issue.detected_at,
                ],
            )?;
            let issue_id = transaction.last_insert_rowid();
            for path in issue.affected_paths {
                transaction.execute(
                    "INSERT INTO issue_paths (issue_id, path, size, currently_exists, note)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        issue_id,
                        path.path,
                        path.size as i64,
                        path.currently_exists,
                        path.note,
                    ],
                )?;
            }
        }

        transaction.execute(
            "UPDATE repositories SET last_scan_at = ?1 WHERE id = ?2",
            params![scan.created_at, scan.repository_id],
        )?;
        transaction.commit()?;

        self.details(scan.repository_id)
    }

    fn initialize(&self) -> Result<()> {
        let conn = self.connection()?;
        run_migrations(&conn)
    }

    fn latest_scan(&self, repository_id: i64) -> Result<Option<ScanSummary>> {
        let conn = self.connection()?;
        conn.query_row(
            "SELECT id, repository_id, created_at, score, score_level, working_tree_size, git_size,
                    total_size, potential_cleanup, security_score, issue_count, score_breakdown
             FROM scans WHERE repository_id = ?1 ORDER BY created_at DESC LIMIT 1",
            params![repository_id],
            scan_from_row,
        )
        .optional()
        .map_err(Into::into)
    }

    fn scan_history(&self, repository_id: i64) -> Result<Vec<ScanSummary>> {
        let conn = self.connection()?;
        let mut stmt = conn.prepare(
            "SELECT id, repository_id, created_at, score, score_level, working_tree_size, git_size,
                    total_size, potential_cleanup, security_score, issue_count, score_breakdown
             FROM scans WHERE repository_id = ?1 ORDER BY created_at DESC LIMIT 20",
        )?;
        let rows = stmt.query_map(params![repository_id], scan_from_row)?;
        let mut scans = Vec::new();
        for row in rows {
            scans.push(row?);
        }
        Ok(scans)
    }

    fn issues(&self, scan_id: i64) -> Result<Vec<Issue>> {
        let conn = self.connection()?;
        let mut stmt = conn.prepare(
            "SELECT id, scan_id, category, severity, title, description, estimated_cleanup, detected_at
             FROM issues WHERE scan_id = ?1 ORDER BY severity DESC, id ASC",
        )?;
        let rows = stmt.query_map(params![scan_id], |row| {
            let issue_id = row.get::<_, i64>(0)?;
            Ok(Issue {
                id: issue_id,
                scan_id: row.get(1)?,
                category: IssueCategory::from_str(&row.get::<_, String>(2)?),
                severity: IssueSeverity::from_str(&row.get::<_, String>(3)?),
                title: row.get(4)?,
                description: row.get(5)?,
                affected_paths: Vec::new(),
                estimated_cleanup_bytes: row.get::<_, i64>(6)? as u64,
                detected_at: row.get(7)?,
            })
        })?;

        let mut issues = Vec::new();
        for row in rows {
            let mut issue = row?;
            issue.affected_paths = self.issue_paths(issue.id)?;
            issues.push(issue);
        }
        Ok(issues)
    }

    fn issue_paths(&self, issue_id: i64) -> Result<Vec<IssuePath>> {
        let conn = self.connection()?;
        let mut stmt = conn.prepare(
            "SELECT path, size, currently_exists, note FROM issue_paths WHERE issue_id = ?1 ORDER BY size DESC",
        )?;
        let rows = stmt.query_map(params![issue_id], |row| {
            Ok(IssuePath {
                path: row.get(0)?,
                size: row.get::<_, i64>(1)? as u64,
                currently_exists: row.get(2)?,
                note: row.get(3)?,
            })
        })?;

        let mut paths = Vec::new();
        for row in rows {
            paths.push(row?);
        }
        Ok(paths)
    }

    fn connection(&self) -> Result<Connection> {
        let conn = Connection::open(&self.db_path)?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        Ok(conn)
    }
}

fn scan_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ScanSummary> {
    let breakdown_json: String = row.get(11)?;
    let score_breakdown =
        serde_json::from_str::<Vec<ScorePenalty>>(&breakdown_json).unwrap_or_default();

    Ok(ScanSummary {
        id: row.get(0)?,
        repository_id: row.get(1)?,
        created_at: row.get(2)?,
        score: row.get(3)?,
        score_level: score_level_from_str(&row.get::<_, String>(4)?),
        working_tree_size: row.get::<_, i64>(5)? as u64,
        git_size: row.get::<_, i64>(6)? as u64,
        total_size: row.get::<_, i64>(7)? as u64,
        potential_cleanup: row.get::<_, i64>(8)? as u64,
        security_score: row.get(9)?,
        issue_count: row.get(10)?,
        score_breakdown,
    })
}

/// Schema migrations, applied in order. Each entry must be safe to run
/// against a database that already has the change applied (e.g. an existing
/// installation that predates this migration list but already has the final
/// schema), since we cannot know for certain which raw schema state an
/// on-disk database that was never version-stamped before is in.
type Migration = fn(&Connection) -> Result<()>;

const MIGRATIONS: &[Migration] = &[migration_v1_initial_schema, migration_v2_add_security_score];

fn run_migrations(conn: &Connection) -> Result<()> {
    conn.execute_batch("PRAGMA foreign_keys = ON;")?;
    let current_version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;

    for (index, migration) in MIGRATIONS.iter().enumerate() {
        let version = (index + 1) as i64;
        if version <= current_version {
            continue;
        }
        migration(conn)?;
        conn.pragma_update(None, "user_version", version)?;
    }

    Ok(())
}

fn migration_v1_initial_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS repositories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            path TEXT NOT NULL UNIQUE,
            added_at TEXT NOT NULL,
            last_scan_at TEXT
        );

        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            repository_id INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
            created_at TEXT NOT NULL,
            score INTEGER NOT NULL,
            score_level TEXT NOT NULL,
            working_tree_size INTEGER NOT NULL,
            git_size INTEGER NOT NULL,
            total_size INTEGER NOT NULL,
            potential_cleanup INTEGER NOT NULL,
            issue_count INTEGER NOT NULL,
            score_breakdown TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS issues (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            category TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            estimated_cleanup INTEGER NOT NULL,
            detected_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS issue_paths (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            issue_id INTEGER NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
            path TEXT NOT NULL,
            size INTEGER NOT NULL,
            currently_exists INTEGER NOT NULL,
            note TEXT
        );
        ",
    )?;
    Ok(())
}

fn migration_v2_add_security_score(conn: &Connection) -> Result<()> {
    ensure_column(
        conn,
        "scans",
        "security_score",
        "INTEGER NOT NULL DEFAULT 100",
    )
}

fn ensure_column(conn: &Connection, table: &str, column: &str, declaration: &str) -> Result<()> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
    for row in rows {
        if row? == column {
            return Ok(());
        }
    }

    conn.execute(
        &format!("ALTER TABLE {table} ADD COLUMN {column} {declaration}"),
        [],
    )?;
    Ok(())
}

fn score_level_to_str(level: ScoreLevel) -> &'static str {
    match level {
        ScoreLevel::Healthy => "Healthy",
        ScoreLevel::Good => "Good",
        ScoreLevel::NeedsAttention => "Needs Attention",
        ScoreLevel::Poor => "Poor",
    }
}

fn score_level_from_str(value: &str) -> ScoreLevel {
    match value {
        "Healthy" => ScoreLevel::Healthy,
        "Good" => ScoreLevel::Good,
        "Needs Attention" => ScoreLevel::NeedsAttention,
        _ => ScoreLevel::Poor,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{IssueCategory, IssueSeverity, NewIssue, NewScan};
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_db_path(name: &str) -> PathBuf {
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "repoglance_test_{name}_{}_{unique}.sqlite3",
            std::process::id()
        ))
    }

    struct TempDb(PathBuf);

    impl Drop for TempDb {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    #[test]
    fn migrations_run_once_and_are_idempotent_on_reopen() {
        let path = temp_db_path("idempotent");
        let _guard = TempDb(path.clone());

        let storage = Storage::new(&path).expect("first open creates schema");
        drop(storage);

        // Reopening an already-migrated database must not error (e.g. by
        // trying to add a column that is already there).
        let storage = Storage::new(&path).expect("second open is a no-op migration-wise");

        let conn = storage.connection().unwrap();
        let user_version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0)).unwrap();
        assert_eq!(user_version, MIGRATIONS.len() as i64);

        let mut stmt = conn.prepare("PRAGMA table_info(scans)").unwrap();
        let has_security_score = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .any(|column| column.map(|name| name == "security_score").unwrap_or(false));
        assert!(has_security_score, "security_score column should exist");
    }

    #[test]
    fn legacy_database_without_security_score_column_gets_migrated() {
        let path = temp_db_path("legacy");
        let _guard = TempDb(path.clone());

        // Simulate a database created before the security_score column (and
        // before this migration list) existed: tables present, but no
        // PRAGMA user_version ever set (defaults to 0).
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "
                CREATE TABLE repositories (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    path TEXT NOT NULL UNIQUE,
                    added_at TEXT NOT NULL,
                    last_scan_at TEXT
                );
                CREATE TABLE scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    repository_id INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
                    created_at TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    score_level TEXT NOT NULL,
                    working_tree_size INTEGER NOT NULL,
                    git_size INTEGER NOT NULL,
                    total_size INTEGER NOT NULL,
                    potential_cleanup INTEGER NOT NULL,
                    issue_count INTEGER NOT NULL,
                    score_breakdown TEXT NOT NULL
                );
                ",
            )
            .unwrap();
        }

        let storage = Storage::new(&path).expect("legacy database should migrate cleanly");
        let conn = storage.connection().unwrap();
        let mut stmt = conn.prepare("PRAGMA table_info(scans)").unwrap();
        let has_security_score = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .any(|column| column.map(|name| name == "security_score").unwrap_or(false));
        assert!(
            has_security_score,
            "legacy database should have security_score added"
        );
    }

    #[test]
    fn save_scan_persists_security_score_and_roundtrips() {
        let path = temp_db_path("roundtrip");
        let _guard = TempDb(path.clone());
        let repo_dir = std::env::temp_dir().join(format!(
            "repoglance_test_repo_{}_{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(repo_dir.join(".git")).unwrap();

        let storage = Storage::new(&path).unwrap();
        let repository = storage.add_repository(&repo_dir).unwrap();

        let scan = NewScan {
            repository_id: repository.id,
            created_at: "2024-01-01T00:00:00Z".into(),
            score: 42,
            score_level: ScoreLevel::from_score(42),
            working_tree_size: 1000,
            git_size: 2000,
            total_size: 3000,
            potential_cleanup: 500,
            security_score: 55,
            issue_count: 1,
            score_breakdown: vec![],
            issues: vec![NewIssue {
                category: IssueCategory::Security,
                severity: IssueSeverity::Critical,
                title: "Possible secrets or sensitive files".into(),
                description: "desc".into(),
                affected_paths: vec![],
                estimated_cleanup_bytes: 0,
                detected_at: "2024-01-01T00:00:00Z".into(),
            }],
        };

        let details = storage.save_scan(scan).unwrap();
        assert_eq!(details.latest_scan.as_ref().unwrap().security_score, 55);

        let refetched = storage.details(repository.id).unwrap();
        assert_eq!(refetched.latest_scan.unwrap().security_score, 55);

        let _ = fs::remove_dir_all(&repo_dir);
    }
}
