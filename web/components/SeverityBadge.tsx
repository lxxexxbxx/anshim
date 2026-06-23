import type { SeverityLevel } from "@/lib/types";

const SEVERITY_STYLES: Record<SeverityLevel, string> = {
  critical: "bg-red-100 text-red-800 border border-red-200",
  high: "bg-orange-100 text-orange-800 border border-orange-200",
  medium: "bg-yellow-100 text-yellow-800 border border-yellow-200",
  low: "bg-blue-100 text-blue-800 border border-blue-200",
  info: "bg-gray-100 text-gray-700 border border-gray-200",
};

const SEVERITY_LABELS: Record<SeverityLevel, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

interface Props {
  severity: SeverityLevel;
  className?: string;
}

export function SeverityBadge({ severity, className = "" }: Props) {
  const style = SEVERITY_STYLES[severity] ?? SEVERITY_STYLES.info;
  const label = SEVERITY_LABELS[severity] ?? severity;
  return (
    <span
      className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${style} ${className}`}
    >
      {label}
    </span>
  );
}
