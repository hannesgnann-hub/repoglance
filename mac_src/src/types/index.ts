export type ScoreLevel = "Healthy" | "Good" | "Needs Attention" | "Poor";

export type IssueSeverity = "info" | "warning" | "critical";

export type IssueCategory =
  | "large_file"
  | "historical_large_file"
  | "generated_artifact"
  | "gitignore"
  | "branch"
  | "repository_size"
  | "security";

export interface IssuePath {
  path: string;
  size: number;
  currently_exists: boolean;
  note?: string | null;
}

export interface Issue {
  id: number;
  scan_id: number;
  category: IssueCategory;
  severity: IssueSeverity;
  title: string;
  description: string;
  affected_paths: IssuePath[];
  estimated_cleanup_bytes: number;
  detected_at: string;
}

export interface ScorePenalty {
  label: string;
  points: number;
  reason: string;
}

export interface ScanSummary {
  id: number;
  repository_id: number;
  created_at: string;
  score: number;
  score_level: ScoreLevel;
  working_tree_size: number;
  git_size: number;
  total_size: number;
  potential_cleanup: number;
  security_score: number;
  issue_count: number;
  score_breakdown: ScorePenalty[];
}

export interface RepositoryOverview {
  id: number;
  name: string;
  path: string;
  added_at: string;
  last_scan_at?: string | null;
  missing: boolean;
  latest_scan?: ScanSummary | null;
}

export interface RepositoryDetails {
  repository: RepositoryOverview;
  latest_scan?: ScanSummary | null;
  issues: Issue[];
  history: ScanSummary[];
}
