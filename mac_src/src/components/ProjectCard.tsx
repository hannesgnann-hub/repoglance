import type { KeyboardEvent, MouseEvent } from "react";
import type { RepositoryOverview } from "../types";
import { formatBytes, formatDate } from "./Format";
import ScoreBadge from "./ScoreBadge";

interface ProjectCardProps {
  repository: RepositoryOverview;
  scanning: boolean;
  onOpen: () => void;
  onToggleFavorite: () => void;
}

export default function ProjectCard({ repository, scanning, onOpen, onToggleFavorite }: ProjectCardProps) {
  const scan = repository.latest_scan;

  function handleToggleFavorite(event: MouseEvent) {
    event.stopPropagation();
    onToggleFavorite();
  }

  function handleKeyDown(event: KeyboardEvent) {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      onOpen();
    }
  }

  return (
    <div
      className={`projectRow ${scanning ? "isScanning" : ""}`}
      onClick={onOpen}
      onKeyDown={handleKeyDown}
      role="button"
      tabIndex={0}
    >
      <button
        className={`starButton ${repository.favorite ? "isFavorite" : ""}`}
        onClick={handleToggleFavorite}
        aria-label={repository.favorite ? "Remove from favorites" : "Add to favorites"}
        aria-pressed={repository.favorite}
        title={repository.favorite ? "Remove from favorites" : "Add to favorites"}
      >
        {repository.favorite ? "★" : "☆"}
      </button>
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
    </div>
  );
}
