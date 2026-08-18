import { formatBytes, formatDateTime } from "../components/Format";
import ScoreBadge from "../components/ScoreBadge";
import type { Issue, RepositoryDetails } from "../types";

interface RepositoryDetailsPageProps {
  details: RepositoryDetails;
  loading: boolean;
  onBack: () => void;
  onScan: () => Promise<void>;
  onLongScan: () => Promise<void>;
  onRemove: () => Promise<void>;
  onOpenIssue: (issue: Issue) => void;
  onOpenIgnored: () => void;
}

export default function RepositoryDetailsPage({
  details,
  loading,
  onBack,
  onScan,
  onLongScan,
  onRemove,
  onOpenIssue,
  onOpenIgnored
}: RepositoryDetailsPageProps) {
  const { repository, latest_scan: scan, issues } = details;

  return (
    <main className="screen">
      <header className="topBar">
        <div className="titleWithBack">
          <button className="plainButton" onClick={onBack}>‹ Projects</button>
          <div>
            <h1>{repository.name}</h1>
            <p>{repository.path}</p>
          </div>
        </div>
        <div className="actions">
          {details.ignored_count > 0 ? (
            <button className="secondaryButton" onClick={onOpenIgnored} disabled={loading}>
              Ignored ({details.ignored_count})
            </button>
          ) : null}
          <button className="secondaryButton" onClick={onRemove} disabled={loading}>
            Remove
          </button>
          <button onClick={onScan} disabled={loading || repository.missing}>
            Scan Again
          </button>
          <button className="secondaryButton" onClick={onLongScan} disabled={loading || repository.missing}>
            Long Scan
          </button>
        </div>
      </header>

      {repository.missing ? (
        <div className="notice error">Repository not found. The saved path no longer exists.</div>
      ) : null}

      <section className="summaryBand">
        <ScoreBadge score={scan?.score} level={scan?.score_level} />
        <div className="statsGrid">
          <div><span>Current files</span><strong>{formatBytes(scan?.working_tree_size)}</strong></div>
          <div><span>Git history</span><strong>{formatBytes(scan?.git_size)}</strong></div>
          <div><span>Total</span><strong>{formatBytes(scan?.total_size)}</strong></div>
          <div><span>Estimated cleanup</span><strong>{formatBytes(scan?.potential_cleanup)}</strong></div>
          <div><span>Security score</span><strong>{scan?.security_score ?? "--"}</strong></div>
        </div>
      </section>

      <section className="twoColumn">
        <div>
          <div className="sectionHeader">
            <h2>Issues</h2>
            <span>{scan ? `${scan.issue_count} found` : "Not scanned"}</span>
          </div>
          <div className="issueList">
            {issues.length === 0 ? (
              <div className="emptyPanel">No obvious cleanup needed.</div>
            ) : (
              issues.map((issue) => (
                <button className="issueRow" key={issue.id} onClick={() => onOpenIssue(issue)}>
                  <span className={`severityDot ${issue.severity}`} />
                  <div>
                    <strong>{issue.title}</strong>
                    <span>{issue.description}</span>
                  </div>
                  <em>{formatBytes(issue.estimated_cleanup_bytes)}</em>
                  <span className="chevron">›</span>
                </button>
              ))
            )}
          </div>
        </div>

        <aside>
          <div className="sectionHeader">
            <h2>Why {scan?.score ?? "--"}?</h2>
          </div>
          <div className="breakdown">
            {(scan?.score_breakdown ?? []).map((item) => (
              <div key={item.label}>
                <span>{item.label}</span>
                <strong>-{item.points}</strong>
                <small>{item.reason}</small>
              </div>
            ))}
            {scan && scan.score_breakdown.length === 0 ? <div className="emptyPanel">No penalties.</div> : null}
          </div>

          <div className="sectionHeader compact">
            <h2>Scan History</h2>
          </div>
          <div className="historyList">
            {details.history.map((item) => (
              <div key={item.id}>
                <span>{formatDateTime(item.created_at)}</span>
                <strong>{item.score}</strong>
              </div>
            ))}
          </div>
        </aside>
      </section>
    </main>
  );
}
