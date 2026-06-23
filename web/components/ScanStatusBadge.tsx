import type { ScanStatus } from "@/lib/types";

const STATUS_STYLES: Record<ScanStatus, string> = {
  running: "bg-blue-100 text-blue-800 border border-blue-200",
  completed: "bg-green-100 text-green-800 border border-green-200",
  failed: "bg-red-100 text-red-800 border border-red-200",
};

const STATUS_LABELS: Record<ScanStatus, string> = {
  running: "실행 중",
  completed: "완료",
  failed: "실패",
};

interface Props {
  status: ScanStatus;
  className?: string;
}

export function ScanStatusBadge({ status, className = "" }: Props) {
  const style = STATUS_STYLES[status] ?? STATUS_STYLES.completed;
  const label = STATUS_LABELS[status] ?? status;
  return (
    <span
      className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${style} ${className}`}
    >
      {label}
    </span>
  );
}
