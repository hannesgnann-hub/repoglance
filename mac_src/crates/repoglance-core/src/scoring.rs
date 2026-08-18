use crate::models::{IssueCategory, NewIssue, ScoreLevel, ScorePenalty};

const GIB: u64 = 1024 * 1024 * 1024;

pub fn calculate_score(
    working_tree_size: u64,
    git_size: u64,
    potential_cleanup: u64,
    issues: &[NewIssue],
) -> (i64, ScoreLevel, Vec<ScorePenalty>) {
    let mut penalties = Vec::new();

    if working_tree_size + git_size > GIB {
        penalties.push(ScorePenalty {
            label: "Storage".into(),
            points: 5,
            reason: "Repository is larger than 1 GB.".into(),
        });
    }

    if git_size > working_tree_size.saturating_mul(2) && git_size > 100 * 1024 * 1024 {
        penalties.push(ScorePenalty {
            label: "Repository size".into(),
            points: 5,
            reason: "Git history is much larger than current files.".into(),
        });
    }

    if potential_cleanup > 500 * 1024 * 1024 {
        penalties.push(ScorePenalty {
            label: "Cleanup potential".into(),
            points: 8,
            reason: "Estimated cleanup potential is above 500 MB.".into(),
        });
    } else if potential_cleanup > 100 * 1024 * 1024 {
        penalties.push(ScorePenalty {
            label: "Cleanup potential".into(),
            points: 4,
            reason: "Estimated cleanup potential is above 100 MB.".into(),
        });
    }

    for category in [
        IssueCategory::HistoricalLargeFile,
        IssueCategory::GeneratedArtifact,
        IssueCategory::Gitignore,
        IssueCategory::Branch,
        IssueCategory::LargeFile,
        IssueCategory::Security,
    ] {
        let matching_issues: Vec<&NewIssue> = issues
            .iter()
            .filter(|issue| {
                issue.category.as_str() == category.as_str()
                    && (!issue.affected_paths.is_empty() || issue.estimated_cleanup_bytes > 0)
            })
            .collect();
        if matching_issues.is_empty() {
            continue;
        }

        // Every matching issue contributes at least one "unit" even when it does not
        // enumerate individual paths (e.g. a repository-size style issue).
        let unit_count: i64 = matching_issues
            .iter()
            .map(|issue| issue.affected_paths.len().max(1) as i64)
            .sum();

        let (label, base, per_extra, max, reason) = match category {
            IssueCategory::HistoricalLargeFile => (
                "History",
                4,
                1,
                12,
                "Large blobs are stored in Git history.",
            ),
            IssueCategory::GeneratedArtifact => (
                "Artifacts",
                2,
                1,
                6,
                "Possible generated artifacts were found.",
            ),
            IssueCategory::Gitignore => (
                ".gitignore",
                1,
                1,
                4,
                "Recommended ignore entries are missing.",
            ),
            IssueCategory::Branch => (
                "Branches",
                1,
                1,
                5,
                "Old merged local branches may need review.",
            ),
            IssueCategory::LargeFile => (
                "Large files",
                2,
                2,
                10,
                "Large files exist in the working tree.",
            ),
            IssueCategory::Security => (
                "Security",
                6,
                4,
                20,
                "Possible secrets or sensitive files were found.",
            ),
            _ => continue,
        };

        penalties.push(ScorePenalty {
            label: label.into(),
            points: scaled_penalty(unit_count, base, per_extra, max),
            reason: reason.into(),
        });
    }

    let total_penalty: i64 = penalties.iter().map(|penalty| penalty.points).sum();
    let score = (100 - total_penalty).clamp(0, 100);
    (score, ScoreLevel::from_score(score), penalties)
}

/// Scales a penalty with the number of affected items: `base` points for the
/// first item, plus `per_extra` points for each additional one, capped at `max`.
fn scaled_penalty(count: i64, base: i64, per_extra: i64, max: i64) -> i64 {
    let extra = (count - 1).max(0);
    (base + per_extra * extra).min(max)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{IssuePath, IssueSeverity};

    fn issue_path(path: &str, size: u64) -> IssuePath {
        IssuePath {
            path: path.into(),
            size,
            currently_exists: true,
            note: None,
        }
    }

    fn issue(category: IssueCategory, paths: Vec<IssuePath>, cleanup: u64) -> NewIssue {
        NewIssue {
            category,
            severity: IssueSeverity::Info,
            title: "issue".into(),
            description: "description".into(),
            affected_paths: paths,
            estimated_cleanup_bytes: cleanup,
            detected_at: "2024-01-01T00:00:00Z".into(),
        }
    }

    #[test]
    fn clean_repository_scores_100() {
        let (score, level, penalties) = calculate_score(1024, 1024, 0, &[]);
        assert_eq!(score, 100);
        assert!(penalties.is_empty());
        assert!(matches!(level, ScoreLevel::Healthy));
    }

    #[test]
    fn single_large_file_penalizes_less_than_many() {
        let one_file = vec![issue(
            IssueCategory::LargeFile,
            vec![issue_path("a.bin", 60_000_000)],
            60_000_000,
        )];
        let many_files = vec![issue(
            IssueCategory::LargeFile,
            (0..10)
                .map(|i| issue_path(&format!("f{i}.bin"), 60_000_000))
                .collect(),
            600_000_000,
        )];

        let (score_one, _, _) = calculate_score(0, 0, 60_000_000, &one_file);
        let (score_many, _, _) = calculate_score(0, 0, 600_000_000, &many_files);

        assert!(
            score_many < score_one,
            "more large files should score worse: {score_many} vs {score_one}"
        );
    }

    #[test]
    fn large_file_penalty_is_capped() {
        let many_files = vec![issue(
            IssueCategory::LargeFile,
            (0..50)
                .map(|i| issue_path(&format!("f{i}.bin"), 60_000_000))
                .collect(),
            0,
        )];
        let (_, _, penalties) = calculate_score(0, 0, 0, &many_files);
        let large_file_penalty = penalties
            .iter()
            .find(|p| p.label == "Large files")
            .expect("penalty present");
        assert_eq!(large_file_penalty.points, 10);
    }

    #[test]
    fn security_findings_are_penalized_hardest_per_item() {
        let one_secret = vec![issue(
            IssueCategory::Security,
            vec![issue_path(".env", 100)],
            0,
        )];
        let one_artifact = vec![issue(
            IssueCategory::GeneratedArtifact,
            vec![issue_path("dist/bundle.js", 100)],
            100,
        )];

        let (_, _, security_penalties) = calculate_score(0, 0, 0, &one_secret);
        let (_, _, artifact_penalties) = calculate_score(0, 0, 100, &one_artifact);

        assert!(security_penalties[0].points > artifact_penalties[0].points);
    }

    #[test]
    fn issue_without_affected_paths_still_counts_as_one_unit() {
        // e.g. an aggregate issue that reports a cleanup estimate without a
        // per-path breakdown should still contribute exactly one penalty unit.
        let issues = vec![issue(IssueCategory::HistoricalLargeFile, vec![], 5_000_000)];
        let (_, _, penalties) = calculate_score(0, 0, 5_000_000, &issues);
        assert_eq!(penalties.len(), 1);
        assert_eq!(penalties[0].points, 4);
    }
}
