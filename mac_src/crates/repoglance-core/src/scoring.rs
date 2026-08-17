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
        let count = issues
            .iter()
            .filter(|issue| {
                issue.category.as_str() == category.as_str()
                    && (!issue.affected_paths.is_empty() || issue.estimated_cleanup_bytes > 0)
            })
            .count();
        if count == 0 {
            continue;
        }

        let (label, points, reason) = match category {
            IssueCategory::HistoricalLargeFile => {
                ("History", 6, "Large blobs are stored in Git history.")
            }
            IssueCategory::GeneratedArtifact => {
                ("Artifacts", 3, "Possible generated artifacts were found.")
            }
            IssueCategory::Gitignore => {
                (".gitignore", 2, "Recommended ignore entries are missing.")
            }
            IssueCategory::Branch => ("Branches", 1, "Old merged local branches may need review."),
            IssueCategory::LargeFile => {
                ("Large files", 3, "Large files exist in the working tree.")
            }
            IssueCategory::Security => (
                "Security",
                10,
                "Possible secrets or sensitive files were found.",
            ),
            _ => continue,
        };

        penalties.push(ScorePenalty {
            label: label.into(),
            points,
            reason: reason.into(),
        });
    }

    let total_penalty: i64 = penalties.iter().map(|penalty| penalty.points).sum();
    let score = (100 - total_penalty).clamp(0, 100);
    (score, ScoreLevel::from_score(score), penalties)
}
