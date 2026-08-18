use std::{
    collections::{BTreeSet, HashMap},
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration as StdDuration, Instant},
};

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Duration, Utc};
use walkdir::WalkDir;

use crate::{
    models::{IssueCategory, IssuePath, IssueSeverity, NewIssue, NewScan},
    scoring::calculate_score,
};

const LARGE_FILE_THRESHOLD: u64 = 50 * 1024 * 1024;
const QUICK_GIT_COMMAND_TIMEOUT: StdDuration = StdDuration::from_secs(15);
const DEEP_GIT_COMMAND_TIMEOUT: StdDuration = StdDuration::from_secs(120);
const QUICK_HISTORY_OBJECT_LIMIT: usize = 120_000;
const DEEP_HISTORY_OBJECT_LIMIT: usize = 500_000;
/// Files larger than this are not read for content-based secret scanning
/// (filename/extension based checks still apply regardless of size).
const SECRET_CONTENT_SCAN_MAX_SIZE: u64 = 1024 * 1024;
/// Upper bound on how many historical blobs get their content fetched and
/// scanned for secret patterns in a single scan, to keep `git cat-file
/// --batch` calls bounded on repositories with a lot of history.
const HISTORY_SECRET_CANDIDATE_LIMIT: usize = 200;

#[derive(Debug, Clone, Copy)]
pub struct ScanOptions {
    pub deep_history: bool,
}

impl ScanOptions {
    pub fn quick() -> Self {
        Self {
            deep_history: false,
        }
    }
}

struct WorkingTreeScan {
    size: u64,
    large_files: Vec<IssuePath>,
    generated_artifacts: Vec<IssuePath>,
    security_risks: Vec<IssuePath>,
}

/// A blob reachable from any ref, as reported by `git rev-list --objects --all`
/// plus `git cat-file --batch-check`.
struct HistoryBlob {
    object_id: String,
    size: u64,
    path: String,
}

enum HistoryScan {
    Blobs(Vec<HistoryBlob>),
    Skipped(NewIssue),
}

pub fn scan_repository_path(repository_id: i64, path: &Path) -> Result<NewScan> {
    scan_repository_path_with_options(repository_id, path, ScanOptions::quick(), &|| false)
}

pub fn scan_repository_path_with_options(
    repository_id: i64,
    path: &Path,
    options: ScanOptions,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<NewScan> {
    if !path.join(".git").exists() {
        return Err(anyhow!(
            "This folder does not appear to be a Git repository."
        ));
    }

    let detected_at = Utc::now().to_rfc3339();
    check_cancelled(is_cancelled)?;
    let working_tree = scan_working_tree(path, is_cancelled)?;
    trace("working tree done");
    let working_tree_size = working_tree.size;
    let git_size = fast_directory_size(&path.join(".git"))?;
    trace("git size done");
    let total_size = working_tree_size.saturating_add(git_size);

    let mut issues = Vec::new();
    issues.extend(repository_size_issue(
        working_tree_size,
        git_size,
        &detected_at,
    ));
    issues.extend(large_current_files(working_tree.large_files, &detected_at));
    issues.extend(historical_git_issues(
        path,
        &detected_at,
        options,
        is_cancelled,
    )?);
    trace("history done");
    issues.extend(generated_artifacts(
        working_tree.generated_artifacts,
        &detected_at,
    ));
    issues.extend(gitignore_recommendations(path, &detected_at)?);
    issues.extend(security_issues(working_tree.security_risks, &detected_at));
    issues.extend(branch_issues(path, &detected_at)?);
    trace("issues done");

    let potential_cleanup = issues
        .iter()
        .map(|issue| issue.estimated_cleanup_bytes)
        .sum::<u64>();
    let security_score = calculate_security_score(&issues);
    let (score, score_level, score_breakdown) =
        calculate_score(working_tree_size, git_size, potential_cleanup, &issues);

    Ok(NewScan {
        repository_id,
        created_at: detected_at,
        score,
        score_level,
        working_tree_size,
        git_size,
        total_size,
        potential_cleanup,
        security_score,
        issue_count: issues.len() as i64,
        score_breakdown,
        issues,
    })
}

fn calculate_security_score(issues: &[NewIssue]) -> i64 {
    let risk_count = issues
        .iter()
        .filter(|issue| issue.category.as_str() == IssueCategory::Security.as_str())
        .flat_map(|issue| issue.affected_paths.iter())
        .count() as i64;
    (100 - (risk_count * 15).min(90)).clamp(0, 100)
}

fn scan_working_tree(path: &Path, is_cancelled: &dyn Fn() -> bool) -> Result<WorkingTreeScan> {
    let mut size = 0_u64;
    let mut large_files = Vec::new();
    let mut generated_artifacts = Vec::new();
    let mut security_risks = Vec::new();
    let mut visited = 0_usize;

    let mut entries = WalkDir::new(path).follow_links(false).into_iter();
    while let Some(entry) = entries.next() {
        visited += 1;
        if visited % 500 == 0 {
            check_cancelled(is_cancelled)?;
        }

        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        if entry.file_name().to_string_lossy() == ".git" {
            entries.skip_current_dir();
            continue;
        }
        if entry.depth() == 0 {
            continue;
        }

        if entry.file_type().is_dir() && is_generated_directory_name(entry.path()) {
            let artifact_size = fast_directory_size(entry.path()).unwrap_or(0);
            size = size.saturating_add(artifact_size);
            generated_artifacts.push(issue_path(
                path,
                entry.path(),
                artifact_size,
                true,
                Some("Possible generated artifact directory".into()),
            ));
            entries.skip_current_dir();
            continue;
        }

        if !entry.file_type().is_file() {
            continue;
        }

        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        let file_size = metadata.len();
        size = size.saturating_add(file_size);

        if file_size >= LARGE_FILE_THRESHOLD {
            large_files.push(issue_path(path, entry.path(), file_size, true, None));
        }

        if let Some(note) = security_note(entry.path(), file_size) {
            security_risks.push(issue_path(path, entry.path(), file_size, true, Some(note)));
        }

        if is_generated_file(entry.path()) {
            generated_artifacts.push(issue_path(
                path,
                entry.path(),
                file_size,
                true,
                Some("Possible generated artifact".into()),
            ));
        }
    }

    generated_artifacts.sort_by(|a, b| b.size.cmp(&a.size));
    generated_artifacts.truncate(100);

    Ok(WorkingTreeScan {
        size,
        large_files,
        generated_artifacts,
        security_risks,
    })
}

fn fast_directory_size(path: &Path) -> Result<u64> {
    #[cfg(unix)]
    {
        let output = Command::new("du")
            .args(["-sk"])
            .arg(path)
            .output()
            .context("failed to run du")?;
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(kib) = stdout
                .split_whitespace()
                .next()
                .and_then(|value| value.parse::<u64>().ok())
            {
                return Ok(kib.saturating_mul(1024));
            }
        }
    }

    directory_size(path, false)
}

fn directory_size(path: &Path, skip_git: bool) -> Result<u64> {
    let mut total = 0_u64;

    for entry in WalkDir::new(path)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| {
            if !skip_git {
                return true;
            }
            entry.file_name().to_string_lossy() != ".git"
        })
    {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        if entry.file_type().is_file() {
            if let Ok(metadata) = entry.metadata() {
                total = total.saturating_add(metadata.len());
            }
        }
    }

    Ok(total)
}

fn repository_size_issue(
    working_tree_size: u64,
    git_size: u64,
    detected_at: &str,
) -> Vec<NewIssue> {
    if git_size <= working_tree_size.saturating_mul(2) || git_size < 100 * 1024 * 1024 {
        return Vec::new();
    }

    vec![NewIssue {
        category: IssueCategory::RepositorySize,
        severity: IssueSeverity::Warning,
        title: "Git history is larger than current files".into(),
        description: "The .git directory is much larger than the current working tree.".into(),
        affected_paths: vec![IssuePath {
            path: ".git".into(),
            size: git_size,
            currently_exists: true,
            note: Some("Read-only size observation".into()),
        }],
        estimated_cleanup_bytes: git_size.saturating_sub(working_tree_size),
        detected_at: detected_at.into(),
    }]
}

fn large_current_files(files: Vec<IssuePath>, detected_at: &str) -> Vec<NewIssue> {
    if files.is_empty() {
        return Vec::new();
    }

    let cleanup = files.iter().map(|file| file.size).sum();
    vec![NewIssue {
        category: IssueCategory::LargeFile,
        severity: IssueSeverity::Warning,
        title: "Large current files".into(),
        description: "Large files exist in the current repository checkout.".into(),
        affected_paths: files,
        estimated_cleanup_bytes: cleanup,
        detected_at: detected_at.into(),
    }]
}

/// Runs the (potentially expensive) history object walk once and derives both
/// the historical-large-file issue and the historical-secret issue from it.
fn historical_git_issues(
    path: &Path,
    detected_at: &str,
    options: ScanOptions,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<NewIssue>> {
    let timeout = if options.deep_history {
        DEEP_GIT_COMMAND_TIMEOUT
    } else {
        QUICK_GIT_COMMAND_TIMEOUT
    };

    match scan_history_blob_metadata(path, detected_at, options, is_cancelled)? {
        HistoryScan::Skipped(issue) => Ok(vec![issue]),
        HistoryScan::Blobs(blobs) => {
            let mut issues = historical_large_files_from_blobs(path, detected_at, &blobs);
            issues.extend(historical_secret_files(
                path,
                detected_at,
                &blobs,
                timeout,
                is_cancelled,
            )?);
            Ok(issues)
        }
    }
}

fn scan_history_blob_metadata(
    path: &Path,
    detected_at: &str,
    options: ScanOptions,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<HistoryScan> {
    let timeout = if options.deep_history {
        DEEP_GIT_COMMAND_TIMEOUT
    } else {
        QUICK_GIT_COMMAND_TIMEOUT
    };
    let object_limit = if options.deep_history {
        DEEP_HISTORY_OBJECT_LIMIT
    } else {
        QUICK_HISTORY_OBJECT_LIMIT
    };

    let objects = match git_output(
        path,
        ["rev-list", "--objects", "--all"],
        timeout,
        is_cancelled,
    ) {
        Ok(objects) => objects,
        Err(error) => {
            return Ok(HistoryScan::Skipped(history_scan_skipped(
                detected_at,
                format!("Git history object enumeration did not finish quickly: {error}"),
            )));
        }
    };
    if objects.trim().is_empty() {
        return Ok(HistoryScan::Blobs(Vec::new()));
    }
    if objects.lines().count() > object_limit {
        return Ok(HistoryScan::Skipped(history_scan_skipped(
            detected_at,
            format!("Git history contains more than {object_limit} objects."),
        )));
    }

    let stdout = match git_output_with_stdin(
        path,
        [
            "cat-file",
            "--batch-check=%(objecttype) %(objectname) %(objectsize) %(rest)",
        ],
        &objects,
        timeout,
        is_cancelled,
    ) {
        Ok(stdout) => stdout,
        Err(_) => {
            return Ok(HistoryScan::Skipped(history_scan_skipped(
                detected_at,
                "Git object inspection did not complete successfully.".into(),
            )));
        }
    };

    let mut blobs = Vec::new();
    for line in stdout.lines() {
        let mut parts = line.splitn(4, ' ');
        let object_type = parts.next().unwrap_or_default();
        let object_id = parts.next().unwrap_or_default();
        let size = parts
            .next()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        let object_path = parts.next().unwrap_or_default();

        if object_type != "blob" || object_path.is_empty() {
            continue;
        }
        blobs.push(HistoryBlob {
            object_id: object_id.to_string(),
            size,
            path: object_path.to_string(),
        });
    }

    Ok(HistoryScan::Blobs(blobs))
}

fn historical_large_files_from_blobs(
    path: &Path,
    detected_at: &str,
    blobs: &[HistoryBlob],
) -> Vec<NewIssue> {
    let mut files = Vec::new();
    let mut seen = BTreeSet::new();

    for blob in blobs {
        if blob.size < LARGE_FILE_THRESHOLD {
            continue;
        }
        let key = format!("{}:{}", blob.path, blob.size);
        if !seen.insert(key) {
            continue;
        }
        let currently_exists = path.join(&blob.path).exists();
        files.push(IssuePath {
            path: blob.path.clone(),
            size: blob.size,
            currently_exists,
            note: Some(if currently_exists {
                "File currently exists".into()
            } else {
                "Deleted but still present in Git history".into()
            }),
        });
    }

    if files.is_empty() {
        return Vec::new();
    }

    let cleanup = files
        .iter()
        .filter(|file| !file.currently_exists)
        .map(|file| file.size)
        .sum();
    vec![NewIssue {
        category: IssueCategory::HistoricalLargeFile,
        severity: IssueSeverity::Warning,
        title: "Historical large files".into(),
        description: "Git stores historical versions of files. Deleting a file from the current project does not automatically remove it from repository history.".into(),
        affected_paths: files,
        estimated_cleanup_bytes: cleanup,
        detected_at: detected_at.into(),
    }]
}

/// Looks for likely secrets among *historical* blobs: filenames/extensions
/// that are always suspicious are flagged directly, while ambiguous text
/// files have their content fetched (bounded by `HISTORY_SECRET_CANDIDATE_LIMIT`)
/// and scanned with the same markers used for the working tree.
fn historical_secret_files(
    path: &Path,
    detected_at: &str,
    blobs: &[HistoryBlob],
    timeout: StdDuration,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<NewIssue>> {
    let mut findings: Vec<IssuePath> = Vec::new();
    let mut seen_paths: BTreeSet<String> = BTreeSet::new();
    let mut content_candidates: Vec<&HistoryBlob> = Vec::new();

    for blob in blobs {
        if seen_paths.contains(&blob.path) {
            continue;
        }
        let blob_path = Path::new(&blob.path);
        if let Some(note) = sensitive_filename_note(blob_path) {
            findings.push(history_secret_path(path, &blob.path, blob.size, note));
            seen_paths.insert(blob.path.clone());
            continue;
        }
        if blob.size <= SECRET_CONTENT_SCAN_MAX_SIZE
            && should_scan_text_content(blob_path)
            && content_candidates.len() < HISTORY_SECRET_CANDIDATE_LIMIT
        {
            content_candidates.push(blob);
        }
    }

    if !content_candidates.is_empty() && !is_cancelled() {
        let ids = content_candidates
            .iter()
            .map(|blob| blob.object_id.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        if let Ok(contents) =
            git_batch_object_contents(path, &ids, timeout, is_cancelled)
        {
            for blob in &content_candidates {
                if seen_paths.contains(&blob.path) {
                    continue;
                }
                let Some(content_bytes) = contents.get(&blob.object_id) else {
                    continue;
                };
                let content = String::from_utf8_lossy(content_bytes);
                if let Some(note) = content_secret_note(&content) {
                    findings.push(history_secret_path(path, &blob.path, blob.size, note));
                    seen_paths.insert(blob.path.clone());
                }
            }
        }
    }

    if findings.is_empty() {
        return Ok(Vec::new());
    }

    Ok(vec![NewIssue {
        category: IssueCategory::Security,
        severity: IssueSeverity::Critical,
        title: "Possible secrets in Git history".into(),
        description: "Files or content patterns that may expose credentials, private keys, tokens, or local environment secrets were found in earlier Git history. Deleting the current file is not enough to remove them; rotate any exposed credentials and consider rewriting history.".into(),
        affected_paths: findings,
        estimated_cleanup_bytes: 0,
        detected_at: detected_at.into(),
    }])
}

fn history_secret_path(root: &Path, object_path: &str, size: u64, note: String) -> IssuePath {
    let currently_exists = root.join(object_path).exists();
    IssuePath {
        path: object_path.into(),
        size,
        currently_exists,
        note: Some(note),
    }
}

fn history_scan_skipped(detected_at: &str, reason: String) -> NewIssue {
    NewIssue {
        category: IssueCategory::HistoricalLargeFile,
        severity: IssueSeverity::Info,
        title: "History scan skipped".into(),
        description: format!("{reason} Current files and generated artifacts were still scanned."),
        affected_paths: Vec::new(),
        estimated_cleanup_bytes: 0,
        detected_at: detected_at.into(),
    }
}

fn generated_artifacts(files: Vec<IssuePath>, detected_at: &str) -> Vec<NewIssue> {
    if files.is_empty() {
        return Vec::new();
    }

    let cleanup = files.iter().map(|file| file.size).sum();
    vec![NewIssue {
        category: IssueCategory::GeneratedArtifact,
        severity: IssueSeverity::Info,
        title: "Generated build artifacts".into(),
        description: "Possible generated artifacts were found in the working tree.".into(),
        affected_paths: files,
        estimated_cleanup_bytes: cleanup,
        detected_at: detected_at.into(),
    }]
}

fn security_issues(files: Vec<IssuePath>, detected_at: &str) -> Vec<NewIssue> {
    if files.is_empty() {
        return Vec::new();
    }

    vec![NewIssue {
        category: IssueCategory::Security,
        severity: IssueSeverity::Critical,
        title: "Possible secrets or sensitive files".into(),
        description: "Files or content patterns were found that may expose credentials, private keys, tokens, or local environment secrets.".into(),
        affected_paths: files,
        estimated_cleanup_bytes: 0,
        detected_at: detected_at.into(),
    }]
}

/// Filename/extension based secret heuristics that need no file content.
fn sensitive_filename_note(path: &Path) -> Option<String> {
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    if matches!(
        file_name.as_str(),
        ".env" | ".env.local" | ".env.production" | ".npmrc" | ".pypirc" | "id_rsa" | "id_ed25519"
    ) {
        return Some("Sensitive filename".into());
    }

    if matches!(extension.as_str(), "pem" | "key" | "p12" | "pfx") {
        return Some("Possible private key or certificate material".into());
    }

    None
}

/// Content-based secret heuristics, shared between working-tree files and
/// historical blob content.
fn content_secret_note(content: &str) -> Option<String> {
    let lower = content.to_ascii_lowercase();
    if content.contains("-----BEGIN") && content.contains("PRIVATE KEY-----") {
        return Some("Private key marker".into());
    }
    if content.contains("AKIA") {
        return Some("Possible AWS access key".into());
    }
    for marker in [
        "api_key",
        "apikey",
        "secret_key",
        "client_secret",
        "access_token",
        "private_token",
        "password=",
        "token=",
    ] {
        if lower.contains(marker) {
            return Some(format!("Possible secret marker: {marker}"));
        }
    }

    None
}

fn security_note(path: &Path, file_size: u64) -> Option<String> {
    if let Some(note) = sensitive_filename_note(path) {
        return Some(note);
    }

    if file_size <= SECRET_CONTENT_SCAN_MAX_SIZE && should_scan_text_content(path) {
        if let Ok(content) = fs::read_to_string(path) {
            return content_secret_note(&content);
        }
    }

    None
}

fn should_scan_text_content(path: &Path) -> bool {
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if matches!(
        file_name.as_str(),
        ".env" | ".env.local" | ".env.production" | ".npmrc" | ".pypirc"
    ) {
        return true;
    }

    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    matches!(
        extension.as_str(),
        "cfg"
            | "conf"
            | "gd"
            | "gradle"
            | "java"
            | "js"
            | "json"
            | "kt"
            | "md"
            | "plist"
            | "properties"
            | "py"
            | "rs"
            | "swift"
            | "toml"
            | "ts"
            | "txt"
            | "xml"
            | "yaml"
            | "yml"
    )
}

fn gitignore_recommendations(path: &Path, detected_at: &str) -> Result<Vec<NewIssue>> {
    let mut recommendations = BTreeSet::new();

    if path.join("Cargo.toml").exists() {
        recommendations.insert("target/");
    }
    if path.join("package.json").exists() {
        recommendations.insert("node_modules/");
        recommendations.insert("dist/");
        recommendations.insert("build/");
    }
    if path.join("pom.xml").exists()
        || path.join("build.gradle").exists()
        || path.join("build.gradle.kts").exists()
    {
        recommendations.insert("target/");
        recommendations.insert("*.class");
    }
    if path.join("requirements.txt").exists() || path.join("pyproject.toml").exists() {
        recommendations.insert("__pycache__/");
        recommendations.insert(".venv/");
        recommendations.insert("*.pyc");
    }
    if path.join("project.godot").exists() {
        recommendations.insert(".godot/");
    }
    recommendations.insert(".DS_Store");

    let gitignore = fs::read_to_string(path.join(".gitignore")).unwrap_or_default();
    let missing = recommendations
        .into_iter()
        .filter(|entry| !gitignore.lines().any(|line| line.trim() == *entry))
        .map(|entry| IssuePath {
            path: entry.into(),
            size: 0,
            currently_exists: false,
            note: Some("Recommended .gitignore entry".into()),
        })
        .collect::<Vec<_>>();

    if missing.is_empty() {
        return Ok(Vec::new());
    }

    Ok(vec![NewIssue {
        category: IssueCategory::Gitignore,
        severity: IssueSeverity::Info,
        title: ".gitignore recommendations".into(),
        description: "Detected project technologies suggest additional ignore entries.".into(),
        affected_paths: missing,
        estimated_cleanup_bytes: 0,
        detected_at: detected_at.into(),
    }])
}

fn branch_issues(path: &Path, detected_at: &str) -> Result<Vec<NewIssue>> {
    let default_branch = default_branch(path).unwrap_or_else(|| "main".into());
    let merged = git_output(
        path,
        ["branch", "--merged", &default_branch],
        QUICK_GIT_COMMAND_TIMEOUT,
        &|| false,
    )
    .unwrap_or_default();
    let merged_names = merged
        .lines()
        .map(|line| line.trim().trim_start_matches('*').trim().to_string())
        .collect::<BTreeSet<_>>();

    let branches = git_output(
        path,
        [
            "branch",
            "--format",
            "%(refname:short)|%(committerdate:iso8601)",
        ],
        QUICK_GIT_COMMAND_TIMEOUT,
        &|| false,
    )
    .unwrap_or_default();
    let cutoff = Utc::now() - Duration::days(180);
    let mut stale = Vec::new();

    for line in branches.lines() {
        let Some((name, date)) = line.split_once('|') else {
            continue;
        };
        if name == default_branch || !merged_names.contains(name) {
            continue;
        }
        let parsed = DateTime::parse_from_str(date.trim(), "%Y-%m-%d %H:%M:%S %z")
            .map(|date| date.with_timezone(&Utc));
        if parsed.map(|date| date > cutoff).unwrap_or(true) {
            continue;
        }
        stale.push(IssuePath {
            path: name.into(),
            size: 0,
            currently_exists: true,
            note: Some(format!("Last commit: {}", date.trim())),
        });
    }

    if stale.is_empty() {
        return Ok(Vec::new());
    }

    Ok(vec![NewIssue {
        category: IssueCategory::Branch,
        severity: IssueSeverity::Info,
        title: "Merged stale branches".into(),
        description: "Old local branches already merged into the default branch may be candidates for manual review.".into(),
        affected_paths: stale,
        estimated_cleanup_bytes: 0,
        detected_at: detected_at.into(),
    }])
}

fn is_generated_directory_name(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };

    matches!(
        name,
        "target" | "node_modules" | "dist" | "build" | "__pycache__" | ".venv" | ".godot"
    )
}

fn is_generated_file(path: &Path) -> bool {
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();

    matches!(
        PathBuf::from(&file_name)
            .extension()
            .and_then(|ext| ext.to_str()),
        Some("class" | "jar" | "pyc" | "exe" | "msi" | "zip" | "tar" | "gz" | "7z")
    ) || file_name == ".ds_store"
}

fn issue_path(
    root: &Path,
    path: &Path,
    size: u64,
    currently_exists: bool,
    note: Option<String>,
) -> IssuePath {
    IssuePath {
        path: path
            .strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .to_string(),
        size,
        currently_exists,
        note,
    }
}

fn default_branch(path: &Path) -> Option<String> {
    let output = git_output(
        path,
        ["symbolic-ref", "--short", "refs/remotes/origin/HEAD"],
        QUICK_GIT_COMMAND_TIMEOUT,
        &|| false,
    )
    .ok()?;
    output.trim().strip_prefix("origin/").map(str::to_string)
}

fn git_output<const N: usize>(
    path: &Path,
    args: [&str; N],
    timeout: StdDuration,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<String> {
    git_output_with_stdin(path, args, "", timeout, is_cancelled)
}

fn git_output_with_stdin<const N: usize>(
    path: &Path,
    args: [&str; N],
    stdin_input: &str,
    timeout: StdDuration,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<String> {
    let bytes =
        git_output_bytes_with_stdin(path, args, stdin_input.as_bytes(), timeout, is_cancelled)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Fetches the content of a batch of Git objects by id via `git cat-file
/// --batch`, keyed by object id. Missing objects are skipped; non-blob
/// objects are skipped too since only blob content is useful for secret
/// scanning.
fn git_batch_object_contents(
    path: &Path,
    object_ids_input: &str,
    timeout: StdDuration,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<HashMap<String, Vec<u8>>> {
    let bytes = git_output_bytes_with_stdin(
        path,
        ["cat-file", "--batch"],
        object_ids_input.as_bytes(),
        timeout,
        is_cancelled,
    )?;
    Ok(parse_batch_output(&bytes))
}

/// Parses the output of `git cat-file --batch`, whose entries look like
/// `<sha> <type> <size>\n<content>\n` (or `<sha> missing\n` for unknown ids).
fn parse_batch_output(data: &[u8]) -> HashMap<String, Vec<u8>> {
    let mut results = HashMap::new();
    let mut idx = 0;

    while idx < data.len() {
        let newline_pos = match data[idx..].iter().position(|&byte| byte == b'\n') {
            Some(offset) => idx + offset,
            None => break,
        };
        let header = String::from_utf8_lossy(&data[idx..newline_pos]).into_owned();
        idx = newline_pos + 1;

        let mut parts = header.split_whitespace();
        let object_id = parts.next().unwrap_or_default().to_string();
        if object_id.is_empty() {
            continue;
        }
        let second = parts.next().unwrap_or_default();
        if second == "missing" {
            continue;
        }
        let object_type = second.to_string();
        let size: usize = match parts.next().and_then(|value| value.parse().ok()) {
            Some(size) => size,
            None => break,
        };

        if idx + size > data.len() {
            break;
        }
        let content = data[idx..idx + size].to_vec();
        idx += size;
        if idx < data.len() && data[idx] == b'\n' {
            idx += 1;
        }

        if object_type == "blob" {
            results.insert(object_id, content);
        }
    }

    results
}

fn git_output_bytes_with_stdin<const N: usize>(
    path: &Path,
    args: [&str; N],
    stdin_input: &[u8],
    timeout: StdDuration,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<u8>> {
    let mut child = Command::new("git")
        .current_dir(path)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to run git")?;

    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("failed to capture git stdout"))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("failed to capture git stderr"))?;
    let stdin = child.stdin.take();
    let stdout_reader = thread::spawn(move || {
        let mut output = Vec::new();
        let _ = stdout.read_to_end(&mut output);
        output
    });
    let stderr_reader = thread::spawn(move || {
        let mut output = String::new();
        let _ = stderr.read_to_string(&mut output);
        output
    });

    // Writing stdin must not happen on this thread: for large inputs (e.g. the
    // full object list piped into `cat-file --batch-check` on a repository
    // with a lot of history) this call can block on the OS pipe buffer for far
    // longer than expected, and if it did that here - before the timeout loop
    // below even starts - neither the timeout nor cancellation could ever
    // interrupt it, hanging the scan regardless of the configured timeout.
    let stdin_input = stdin_input.to_vec();
    let stdin_writer = thread::spawn(move || {
        if let Some(mut stdin) = stdin {
            let _ = stdin.write_all(&stdin_input);
        }
    });

    let started_at = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            let stdout = stdout_reader.join().unwrap_or_default();
            let stderr = stderr_reader.join().unwrap_or_default();
            let _ = stdin_writer.join();
            if !status.success() {
                return Err(anyhow!(stderr.trim().to_string()));
            }
            return Ok(stdout);
        }

        if is_cancelled() {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            let _ = stdin_writer.join();
            return Err(anyhow!("scan cancelled"));
        }

        if started_at.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            let _ = stdin_writer.join();
            return Err(anyhow!("git command timed out"));
        }

        thread::sleep(StdDuration::from_millis(25));
    }
}

fn check_cancelled(is_cancelled: &dyn Fn() -> bool) -> Result<()> {
    if is_cancelled() {
        return Err(anyhow!("Scan cancelled."));
    }

    Ok(())
}

fn trace(message: &str) {
    if std::env::var_os("REPOGLANCE_TRACE").is_some() {
        eprintln!("repoglance trace: {message}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression test for a bug where `stdin.write_all()` ran synchronously
    /// on the calling thread, before the timeout/cancellation loop started.
    /// For large payloads (e.g. the full object list piped into
    /// `cat-file --batch-check` on a repository with a lot of history) that
    /// write could block on the OS pipe buffer independently of - and
    /// unprotected by - the configured timeout, hanging the scan regardless
    /// of quick vs. deep mode. The write now happens on its own thread so the
    /// timeout loop always runs concurrently with it.
    #[test]
    fn git_output_with_stdin_survives_stdin_larger_than_pipe_buffer() {
        let dir = std::env::temp_dir().join(format!(
            "repoglance_scanner_test_large_stdin_{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let run_git = |args: &[&str]| {
            Command::new("git")
                .current_dir(&dir)
                .env("GIT_AUTHOR_NAME", "test")
                .env("GIT_AUTHOR_EMAIL", "test@example.com")
                .env("GIT_COMMITTER_NAME", "test")
                .env("GIT_COMMITTER_EMAIL", "test@example.com")
                .args(args)
                .status()
                .unwrap()
        };
        assert!(run_git(&["init", "-q"]).success());
        fs::write(dir.join("file.txt"), b"hello").unwrap();
        assert!(run_git(&["add", "."]).success());
        assert!(run_git(&["commit", "-q", "-m", "init"]).success());

        // Several times the typical 64KB pipe buffer, so the write cannot
        // complete without the concurrent stdout drain keeping the child
        // able to make progress.
        let object_count = 50_000;
        let large_input = "HEAD\n".repeat(object_count);

        let started = Instant::now();
        let output = git_output_with_stdin(
            &dir,
            ["cat-file", "--batch-check=%(objecttype)"],
            &large_input,
            StdDuration::from_secs(10),
            &|| false,
        )
        .unwrap();

        assert!(
            started.elapsed() < StdDuration::from_secs(9),
            "should complete well before the timeout, not hang until it"
        );
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), object_count);
        assert!(lines.iter().all(|line| *line == "commit"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn sensitive_filename_note_flags_dotenv() {
        assert!(sensitive_filename_note(Path::new(".env")).is_some());
        assert!(sensitive_filename_note(Path::new("config/.env.production")).is_some());
        assert!(sensitive_filename_note(Path::new("id_rsa")).is_some());
        assert!(sensitive_filename_note(Path::new("README.md")).is_none());
    }

    #[test]
    fn sensitive_filename_note_flags_key_extensions() {
        assert!(sensitive_filename_note(Path::new("certs/server.pem")).is_some());
        assert!(sensitive_filename_note(Path::new("client.p12")).is_some());
        assert!(sensitive_filename_note(Path::new("notes.txt")).is_none());
    }

    #[test]
    fn content_secret_note_detects_known_markers() {
        assert!(content_secret_note("-----BEGIN RSA PRIVATE KEY-----").is_some());
        assert!(content_secret_note("aws_key = AKIAABCDEFGHIJKLMNOP").is_some());
        assert!(content_secret_note("API_KEY=abcdef123456").is_some());
        assert!(content_secret_note("just a normal readme").is_none());
    }

    #[test]
    fn should_scan_text_content_covers_common_source_extensions() {
        assert!(should_scan_text_content(Path::new("src/main.rs")));
        assert!(should_scan_text_content(Path::new(".npmrc")));
        assert!(!should_scan_text_content(Path::new("image.png")));
    }

    #[test]
    fn is_generated_file_matches_known_extensions() {
        assert!(is_generated_file(Path::new("Main.class")));
        assert!(is_generated_file(Path::new("archive.tar")));
        assert!(is_generated_file(Path::new(".DS_Store")));
        assert!(!is_generated_file(Path::new("main.rs")));
    }

    #[test]
    fn is_generated_directory_name_matches_known_names() {
        assert!(is_generated_directory_name(Path::new("/repo/node_modules")));
        assert!(is_generated_directory_name(Path::new("/repo/target")));
        assert!(!is_generated_directory_name(Path::new("/repo/src")));
    }

    #[test]
    fn parse_batch_output_extracts_blob_content_and_skips_missing() {
        let mut data = Vec::new();
        data.extend_from_slice(b"aaaa blob 5\nhello\n");
        data.extend_from_slice(b"bbbb missing\n");
        data.extend_from_slice(b"cccc tree 4\nabcd\n");

        let parsed = parse_batch_output(&data);

        assert_eq!(parsed.get("aaaa").map(|v| v.as_slice()), Some(&b"hello"[..]));
        assert!(!parsed.contains_key("bbbb"));
        assert!(!parsed.contains_key("cccc"));
    }

    #[test]
    fn parse_batch_output_handles_binary_content() {
        let mut data = Vec::new();
        data.extend_from_slice(b"deadbeef blob 4\n");
        data.extend_from_slice(&[0u8, 159, 146, 150]);
        data.push(b'\n');

        let parsed = parse_batch_output(&data);

        assert_eq!(
            parsed.get("deadbeef").map(|v| v.as_slice()),
            Some(&[0u8, 159, 146, 150][..])
        );
    }
}
