import type { RepositoryOverview } from "../types";
import { formatBytes, formatDate } from "./Format";
import ScoreBadge from "./ScoreBadge";

interface ProjectCardProps {
  repository: RepositoryOverview;
  scanning: boolean;
  onOpen: () => void;
}

export default function ProjectCard({ repository, scanning, onOpen }: ProjectCardProps) {
  const scan = repository.latest_scan;

  return (
    <button className={`projectRow ${scanning ? "isScanning" : ""}`} onClick={onOpen}>
      <div className="projectIdentity">
        <strong>{repository.name}</strong>
        <span>{scanning ? "Scanning repository..." : repository.missing ? "Repository not found" : repository.path}</span>
      </div>
      <ScoreBadge score={scan?.score} level={scan?.score_level} scanning={scanning} />
      <div className="metric">
        <span>Total</span>
        <strong>{formatBytes(scan?.total_size)}</strong>
      </div>
      <div className="metric">
        <span>Cleanup</span>
        <strong>{formatBytes(scan?.potential_cleanup)}</strong>
      </div>
      <div className="metric securityMetric">
        <span>Security</span>
        <strong>{scan?.security_score ?? "--"}</strong>
      </div>
      <div className="metric">
        <span>Issues</span>
        <strong>{scan?.issue_count ?? 0}</strong>
      </div>
      <div className="metric">
        <span>Last scan</span>
        <strong>{formatDate(repository.last_scan_at)}</strong>
      </div>
      <span className="chevron">›</span>
    </button>
  );
}
