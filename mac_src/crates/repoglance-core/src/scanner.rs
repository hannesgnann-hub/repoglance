use std::{
    collections::BTreeSet,
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
    let git_size = directory_size(&path.join(".git"), false)?;
    trace("git size done");
    let total_size = working_tree_size.saturating_add(git_size);

    let mut issues = Vec::new();
    issues.extend(repository_size_issue(
        working_tree_size,
        git_size,
        &detected_at,
    ));
    issues.extend(large_current_files(working_tree.large_files, &detected_at));
    issues.extend(historical_large_files(
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

fn historical_large_files(
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
            return Ok(vec![history_scan_skipped(
                detected_at,
                format!("Git history object enumeration did not finish quickly: {error}"),
            )]);
        }
    };
    if objects.trim().is_empty() {
        return Ok(Vec::new());
    }
    if objects.lines().count() > object_limit {
        return Ok(vec![history_scan_skipped(
            detected_at,
            format!("Git history contains more than {object_limit} objects."),
        )]);
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
            return Ok(vec![history_scan_skipped(
                detected_at,
                "Git object inspection did not complete successfully.".into(),
            )]);
        }
    };
    let mut files = Vec::new();
    let mut seen = BTreeSet::new();

    for line in stdout.lines() {
        let mut parts = line.splitn(4, ' ');
        let object_type = parts.next().unwrap_or_default();
        let _object_id = parts.next();
        let size = parts
            .next()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        let object_path = parts.next().unwrap_or_default();

        if object_type != "blob" || size < LARGE_FILE_THRESHOLD || object_path.is_empty() {
            continue;
        }
        let key = format!("{object_path}:{size}");
        if !seen.insert(key) {
            continue;
        }
        let currently_exists = path.join(object_path).exists();
        files.push(IssuePath {
            path: object_path.into(),
            size,
            currently_exists,
            note: Some(if currently_exists {
                "File currently exists".into()
            } else {
                "Deleted but still present in Git history".into()
            }),
        });
    }

    if files.is_empty() {
        return Ok(Vec::new());
    }

    let cleanup = files
        .iter()
        .filter(|file| !file.currently_exists)
        .map(|file| file.size)
        .sum();
    Ok(vec![NewIssue {
        category: IssueCategory::HistoricalLargeFile,
        severity: IssueSeverity::Warning,
        title: "Historical large files".into(),
        description: "Git stores historical versions of files. Deleting a file from the current project does not automatically remove it from repository history.".into(),
        affected_paths: files,
        estimated_cleanup_bytes: cleanup,
        detected_at: detected_at.into(),
    }])
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

fn security_note(path: &Path, file_size: u64) -> Option<String> {
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

    if file_size <= 1024 * 1024 && should_scan_text_content(path) {
        if let Ok(content) = fs::read_to_string(path) {
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
    let stdout_reader = thread::spawn(move || {
        let mut output = String::new();
        let _ = stdout.read_to_string(&mut output);
        output
    });
    let stderr_reader = thread::spawn(move || {
        let mut output = String::new();
        let _ = stderr.read_to_string(&mut output);
        output
    });

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(stdin_input.as_bytes())?;
    }

    let started_at = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            let stdout = stdout_reader.join().unwrap_or_default();
            let stderr = stderr_reader.join().unwrap_or_default();
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
            return Err(anyhow!("scan cancelled"));
        }

        if started_at.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
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
