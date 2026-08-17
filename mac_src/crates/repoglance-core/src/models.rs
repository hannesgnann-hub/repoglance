use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepositoryOverview {
    pub id: i64,
    pub name: String,
    pub path: String,
    pub added_at: String,
    pub last_scan_at: Option<String>,
    pub missing: bool,
    pub latest_scan: Option<ScanSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepositoryDetails {
    pub repository: RepositoryOverview,
    pub latest_scan: Option<ScanSummary>,
    pub issues: Vec<Issue>,
    pub history: Vec<ScanSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub id: i64,
    pub repository_id: i64,
    pub created_at: String,
    pub score: i64,
    pub score_level: ScoreLevel,
    pub working_tree_size: u64,
    pub git_size: u64,
    pub total_size: u64,
    pub potential_cleanup: u64,
    pub security_score: i64,
    pub issue_count: i64,
    pub score_breakdown: Vec<ScorePenalty>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewScan {
    pub repository_id: i64,
    pub created_at: String,
    pub score: i64,
    pub score_level: ScoreLevel,
    pub working_tree_size: u64,
    pub git_size: u64,
    pub total_size: u64,
    pub potential_cleanup: u64,
    pub security_score: i64,
    pub issue_count: i64,
    pub score_breakdown: Vec<ScorePenalty>,
    pub issues: Vec<NewIssue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewIssue {
    pub category: IssueCategory,
    pub severity: IssueSeverity,
    pub title: String,
    pub description: String,
    pub affected_paths: Vec<IssuePath>,
    pub estimated_cleanup_bytes: u64,
    pub detected_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Issue {
    pub id: i64,
    pub scan_id: i64,
    pub category: IssueCategory,
    pub severity: IssueSeverity,
    pub title: String,
    pub description: String,
    pub affected_paths: Vec<IssuePath>,
    pub estimated_cleanup_bytes: u64,
    pub detected_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuePath {
    pub path: String,
    pub size: u64,
    pub currently_exists: bool,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScorePenalty {
    pub label: String,
    pub points: i64,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ScoreLevel {
    Healthy,
    Good,
    #[serde(rename = "Needs Attention")]
    NeedsAttention,
    Poor,
}

impl ScoreLevel {
    pub fn from_score(score: i64) -> Self {
        match score {
            90..=100 => Self::Healthy,
            75..=89 => Self::Good,
            50..=74 => Self::NeedsAttention,
            _ => Self::Poor,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssueCategory {
    LargeFile,
    HistoricalLargeFile,
    GeneratedArtifact,
    Gitignore,
    Branch,
    RepositorySize,
    Security,
}

impl IssueCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LargeFile => "large_file",
            Self::HistoricalLargeFile => "historical_large_file",
            Self::GeneratedArtifact => "generated_artifact",
            Self::Gitignore => "gitignore",
            Self::Branch => "branch",
            Self::RepositorySize => "repository_size",
            Self::Security => "security",
        }
    }

    pub fn from_str(value: &str) -> Self {
        match value {
            "large_file" => Self::LargeFile,
            "historical_large_file" => Self::HistoricalLargeFile,
            "generated_artifact" => Self::GeneratedArtifact,
            "gitignore" => Self::Gitignore,
            "branch" => Self::Branch,
            "repository_size" => Self::RepositorySize,
            "security" => Self::Security,
            _ => Self::RepositorySize,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssueSeverity {
    Info,
    Warning,
    Critical,
}

impl IssueSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }

    pub fn from_str(value: &str) -> Self {
        match value {
            "critical" => Self::Critical,
            "warning" => Self::Warning,
            _ => Self::Info,
        }
    }
}
