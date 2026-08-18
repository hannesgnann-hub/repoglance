import { formatDateTime } from "../components/Format";
import type { IgnoredFinding, RepositoryOverview } from "../types";

interface IgnoredFindingsPageProps {
  repository: RepositoryOverview;
  findings: IgnoredFinding[];
  loading: boolean;
  onBack: () => void;
  onUnignore: (id: number) => Promise<void>;
}

const CATEGORY_LABELS: Record<string, string> = {
  large_file: "Large file",
  historical_large_file: "Historical large file",
  generated_artifact: "Generated artifact",
  gitignore: ".gitignore recommendation",
  branch: "Branch",
  repository_size: "Repository size",
  security: "Security"
};

export default function IgnoredFindingsPage({
  repository,
  findings,
  loading,
  onBack,
  onUnignore
}: IgnoredFindingsPageProps) {
  return (
    <main className="screen narrow">
      <header className="topBar">
        <div className="titleWithBack">
          <button className="plainButton" onClick={onBack}>‹ {repository.name}</button>
          <div>
            <h1>Ignored findings</h1>
            <p>{findings.length} item(s) excluded from future scans and the score.</p>
          </div>
        </div>
      </header>

      <section className="detailBlock">
        <div className="fileList">
          {findings.length === 0 ? (
            <div className="emptyPanel">Nothing ignored yet.</div>
          ) : (
            findings.map((finding) => (
              <div key={finding.id}>
                <div>
                  <strong>{finding.path}</strong>
                  <span>{CATEGORY_LABELS[finding.category] ?? finding.category}</span>
                  <small>Ignored {formatDateTime(finding.ignored_at)}</small>
                </div>
                <div className="fileActions">
                  <button
                    className="secondaryButton"
                    onClick={() => onUnignore(finding.id)}
                    disabled={loading}
                  >
                    Un-ignore
                  </button>
                </div>
              </div>
            ))
          )}
        </div>
      </section>

      <section className="detailBlock">
        <h2>What this means</h2>
        <p>
          Ignored paths are excluded from scan results and the health score for this repository. Nothing
          on disk or in Git history was changed - un-ignore a path here to have it show up again the next
          time this repository is scanned.
        </p>
      </section>
    </main>
  );
}
