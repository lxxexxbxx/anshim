"use client";

import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useEffect, useMemo, useState } from "react";
import { ComplianceChart } from "@/components/ComplianceChart";
import { ScanStatusBadge } from "@/components/ScanStatusBadge";
import { SeverityBadge } from "@/components/SeverityBadge";
import { api } from "@/lib/api";
import type { ScanDetail, SeverityLevel, Vulnerability } from "@/lib/types";

function SeverityStatCard({
  severity,
  count,
}: {
  severity: SeverityLevel;
  count: number;
}) {
  const colors: Record<SeverityLevel, string> = {
    critical: "border-red-200 bg-red-50",
    high: "border-orange-200 bg-orange-50",
    medium: "border-yellow-200 bg-yellow-50",
    low: "border-blue-200 bg-blue-50",
    info: "border-gray-200 bg-gray-50",
  };
  return (
    <div className={`rounded-xl border p-5 ${colors[severity]}`}>
      <SeverityBadge severity={severity} />
      <p className="text-3xl font-bold text-slate-900 mt-2">{count}</p>
      <p className="text-xs text-slate-500">건</p>
    </div>
  );
}

export default function ScanDetailPage() {
  const params = useParams();
  const router = useRouter();
  const scanId = params.id as string;

  const [scan, setScan] = useState<ScanDetail | null>(null);
  const [vulns, setVulns] = useState<Vulnerability[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>("all");

  useEffect(() => {
    Promise.all([api.getScan(scanId), api.listVulnerabilities(scanId)])
      .then(([scanData, vulnsData]) => {
        setScan(scanData);
        setVulns(vulnsData);
      })
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false));
  }, [scanId]);

  const filteredVulns = useMemo(() => {
    if (severityFilter === "all") return vulns;
    return vulns.filter((v) => v.severity === severityFilter);
  }, [vulns, severityFilter]);

  const complianceData = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const v of vulns) {
      for (const m of v.compliance_mappings) {
        const key = m.compliance_category ?? m.compliance_id;
        counts[key] = (counts[key] ?? 0) + 1;
      }
    }
    return Object.entries(counts)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 10)
      .map(([category, count]) => ({ category, count }));
  }, [vulns]);

  const handleDelete = async () => {
    if (!confirm("이 스캔 기록을 삭제하시겠습니까?")) return;
    await api.deleteScan(scanId);
    router.push("/");
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-slate-500 text-sm">로딩 중...</div>
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div className="bg-red-50 border border-red-200 rounded-xl p-6 text-center">
        <p className="text-red-700 font-medium">스캔 정보를 불러올 수 없습니다</p>
        <p className="text-red-500 text-sm mt-1">{error}</p>
        <Link href="/" className="mt-4 inline-block text-blue-600 text-sm hover:underline">
          대시보드로 돌아가기
        </Link>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      {/* 헤더 */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Link href="/" className="text-slate-400 text-sm hover:text-blue-600">
              대시보드
            </Link>
            <span className="text-slate-300">/</span>
            <span className="text-slate-600 text-sm">스캔 상세</span>
          </div>
          <h1 className="text-xl font-bold text-slate-900 break-all">{scan.target_path}</h1>
          <div className="flex items-center gap-3 mt-2">
            <ScanStatusBadge status={scan.status} />
            <span className="text-xs text-slate-400 font-mono">{scan.id.slice(0, 8)}</span>
            <span className="text-xs text-slate-400">
              {new Date(scan.started_at).toLocaleString("ko-KR")}
            </span>
          </div>
        </div>
        <button
          onClick={handleDelete}
          className="text-sm text-red-500 hover:text-red-700 border border-red-200 hover:border-red-300 rounded-lg px-3 py-1.5 transition-colors"
        >
          삭제
        </button>
      </div>

      {/* 스캔 메타 정보 */}
      <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-5">
        <h2 className="text-sm font-semibold text-slate-700 mb-3">스캔 정보</h2>
        <dl className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
          <div>
            <dt className="text-slate-400 text-xs">분석 모델</dt>
            <dd className="font-medium text-slate-700 mt-0.5">{scan.model_used ?? "규칙 기반"}</dd>
          </div>
          <div>
            <dt className="text-slate-400 text-xs">컴플라이언스</dt>
            <dd className="font-medium text-slate-700 mt-0.5">
              {(scan.compliance_types ?? []).join(", ") || "-"}
            </dd>
          </div>
          <div>
            <dt className="text-slate-400 text-xs">스캔 파일</dt>
            <dd className="font-medium text-slate-700 mt-0.5">{scan.total_files}개</dd>
          </div>
          <div>
            <dt className="text-slate-400 text-xs">총 취약점</dt>
            <dd className="font-bold text-slate-900 mt-0.5">{scan.total_vulnerabilities}개</dd>
          </div>
        </dl>
      </div>

      {/* 심각도별 통계 */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <SeverityStatCard severity="critical" count={scan.critical_count} />
        <SeverityStatCard severity="high" count={scan.high_count} />
        <SeverityStatCard severity="medium" count={scan.medium_count} />
        <SeverityStatCard severity="low" count={scan.low_count} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* 취약점 목록 */}
        <div className="lg:col-span-2 bg-white rounded-xl border border-slate-200 shadow-sm">
          <div className="px-6 py-4 border-b border-slate-100 flex items-center justify-between">
            <h2 className="text-base font-semibold text-slate-800">취약점 목록</h2>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="text-sm border border-slate-200 rounded-lg px-3 py-1.5 bg-white text-slate-700"
            >
              <option value="all">전체 ({vulns.length})</option>
              <option value="critical">Critical ({scan.critical_count})</option>
              <option value="high">High ({scan.high_count})</option>
              <option value="medium">Medium ({scan.medium_count})</option>
              <option value="low">Low ({scan.low_count})</option>
            </select>
          </div>
          <div className="divide-y divide-slate-50">
            {filteredVulns.map((vuln) => (
              <Link
                key={vuln.id}
                href={`/scans/${scanId}/vulnerabilities/${vuln.id}`}
                className="flex items-start gap-4 px-6 py-4 hover:bg-slate-50 transition-colors group"
              >
                <SeverityBadge severity={vuln.severity as SeverityLevel} className="mt-0.5 flex-shrink-0" />
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-medium text-slate-800 group-hover:text-blue-600 truncate">
                    {vuln.title}
                  </p>
                  <p className="text-xs text-slate-400 mt-0.5 truncate">
                    {vuln.file_path}
                    {vuln.line_start != null && `:${vuln.line_start}`}
                  </p>
                  {vuln.compliance_mappings.length > 0 && (
                    <div className="flex flex-wrap gap-1 mt-1.5">
                      {vuln.compliance_mappings.slice(0, 3).map((m) => (
                        <span
                          key={m.id}
                          className="text-xs bg-indigo-50 text-indigo-700 px-1.5 py-0.5 rounded border border-indigo-100"
                        >
                          {m.compliance_id}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              </Link>
            ))}
            {filteredVulns.length === 0 && (
              <p className="text-slate-400 text-sm text-center py-10">
                해당 조건의 취약점이 없습니다
              </p>
            )}
          </div>
        </div>

        {/* 컴플라이언스 차트 */}
        <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-6">
          <h2 className="text-base font-semibold text-slate-800 mb-4">컴플라이언스 현황</h2>
          <ComplianceChart data={complianceData} title="" />
        </div>
      </div>
    </div>
  );
}
