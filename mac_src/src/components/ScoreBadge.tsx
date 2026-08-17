import type { ScoreLevel } from "../types";

interface ScoreBadgeProps {
  score?: number | null;
  level?: ScoreLevel | null;
  scanning?: boolean;
}

export default function ScoreBadge({ score, level, scanning = false }: ScoreBadgeProps) {
  const label = scanning ? "…" : score == null ? "--" : String(score);
  const tone =
    scanning
      ? "scanning"
      : score == null
      ? "unknown"
      : score >= 90
        ? "healthy"
        : score >= 75
          ? "good"
          : score >= 50
            ? "attention"
            : "poor";

  return (
    <div className={`scoreBadge ${tone}`} aria-label={`Health score ${label}`}>
      <span>{label}</span>
      <small>{scanning ? "Scanning" : level ?? "Not scanned"}</small>
    </div>
  );
}
