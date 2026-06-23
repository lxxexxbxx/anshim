"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import { ScanStatusBadge } from "@/components/ScanStatusBadge";
import { SeverityBadge } from "@/components/SeverityBadge";
import { api } from "@/lib/api";
import type { Scan, SeverityLevel, Stats } from "@/lib/types";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#dc2626",
  high: "#ea580c",
  medium: "#ca8a04",
  low: "#2563eb",
  info: "#6b7280",
};

function StatCard({ label, value, sub }: { label: string; value: string | number; sub?: string }) {
  return (
    <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-6">
      <p className="text-sm text-slate-500 font-medium">{label}</p>
      <p className="text-3xl font-bold text-slate-900 mt-1">{value}</p>
      {sub && <p className="text-xs text-slate-400 mt-1">{sub}</p>}
    </div>
  );
}

export default function DashboardPage() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([api.getStats(), api.listScans(20)])
      .then(([statsData, scanData]) => {
        setStats(statsData);
        setScans(scanData.items);
      })
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-slate-500 text-sm">로딩 중...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-50 border border-red-200 rounded-xl p-6 text-center">
        <p className="text-red-700 font-medium">API 연결 실패</p>
        <p className="text-red-500 text-sm mt-1">{error}</p>
        <p className="text-slate-500 text-xs mt-3">
          <code>anshim serve</code> 명령어로 서버가 실행 중인지 확인하세요
        </p>
      </div>
    );
  }

  const pieData = stats
    ? Object.entries(stats.severity_distribution)
        .filter(([, v]) => v > 0)
        .map(([name, value]) => ({ name, value }))
    : [];

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-bold text-slate-900">보안 감사 대시보드</h1>
        <p className="text-slate-500 text-sm mt-1">ISMS/ISMS-P 컴플라이언스 코드 분석 현황</p>
      </div>

      {/* 통계 카드 */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="총 스캔" value={stats?.total_scans ?? 0} />
        <StatCard label="총 취약점" value={stats?.total_vulnerabilities ?? 0} />
        <StatCard
          label="Critical"
          value={stats?.severity_distribution.critical ?? 0}
          sub="즉시 조치 필요"
        />
        <StatCard
          label="High"
          value={stats?.severity_distribution.high ?? 0}
          sub="높은 위험도"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* 심각도 분포 파이 차트 */}
        <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-6">
          <h2 className="text-base font-semibold text-slate-800 mb-4">심각도 분포</h2>
          {pieData.length > 0 ? (
            <ResponsiveContainer width="100%" height={240}>
              <PieChart>
                <Pie
                  data={pieData}
                  dataKey="value"
                  nameKey="name"
                  cx="50%"
                  cy="50%"
                  outerRadius={90}
                  label={({ name, percent }) =>
                    `${name} ${(percent * 100).toFixed(0)}%`
                  }
                >
                  {pieData.map((entry) => (
                    <Cell
                      key={entry.name}
                      fill={SEVERITY_COLORS[entry.name] ?? "#6b7280"}
                    />
                  ))}
                </Pie>
                <Tooltip formatter={(v: number) => [`${v}개`, "취약점"]} />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-40 text-slate-400 text-sm">
              스캔 결과 없음
            </div>
          )}
        </div>

        {/* 최근 스캔 목록 */}
        <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-6">
          <h2 className="text-base font-semibold text-slate-800 mb-4">최근 스캔</h2>
          <div className="space-y-3">
            {(stats?.recent_scans ?? []).map((scan) => (
              <Link
                key={scan.id}
                href={`/scans/${scan.id}`}
                className="flex items-start justify-between p-3 rounded-lg hover:bg-slate-50 transition-colors border border-slate-100 group"
              >
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-medium text-slate-800 truncate group-hover:text-blue-600">
                    {scan.target_path}
                  </p>
                  <p className="text-xs text-slate-400 mt-0.5">
                    {new Date(scan.started_at).toLocaleString("ko-KR")}
                  </p>
                </div>
                <div className="ml-3 flex-shrink-0 flex items-center gap-2">
                  <span className="text-xs font-bold text-red-600">
                    {scan.total_vulnerabilities}건
                  </span>
                  <ScanStatusBadge status={scan.status} />
                </div>
              </Link>
            ))}
            {(stats?.recent_scans ?? []).length === 0 && (
              <p className="text-slate-400 text-sm text-center py-8">
                아직 스캔 기록이 없습니다
              </p>
            )}
          </div>
        </div>
      </div>

      {/* 전체 스캔 목록 */}
      <div className="bg-white rounded-xl border border-slate-200 shadow-sm">
        <div className="px-6 py-4 border-b border-slate-100">
          <h2 className="text-base font-semibold text-slate-800">전체 스캔 목록</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="bg-slate-50 border-b border-slate-100">
                <th className="text-left text-xs font-semibold text-slate-500 uppercase tracking-wider px-6 py-3">
                  스캔 경로
                </th>
                <th className="text-left text-xs font-semibold text-slate-500 uppercase tracking-wider px-4 py-3">
                  상태
                </th>
                <th className="text-left text-xs font-semibold text-slate-500 uppercase tracking-wider px-4 py-3">
                  취약점
                </th>
                <th className="text-left text-xs font-semibold text-slate-500 uppercase tracking-wider px-4 py-3">
                  심각도
                </th>
                <th className="text-left text-xs font-semibold text-slate-500 uppercase tracking-wider px-4 py-3">
                  시각
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-50">
              {scans.map((scan) => (
                <tr key={scan.id} className="hover:bg-slate-50 transition-colors">
                  <td className="px-6 py-4">
                    <Link
                      href={`/scans/${scan.id}`}
                      className="text-sm font-medium text-blue-600 hover:text-blue-800 block max-w-xs truncate"
                    >
                      {scan.target_path}
                    </Link>
                    <span className="text-xs text-slate-400 font-mono">{scan.id.slice(0, 8)}</span>
                  </td>
                  <td className="px-4 py-4">
                    <ScanStatusBadge status={scan.status} />
                  </td>
                  <td className="px-4 py-4 text-sm font-medium text-slate-700">
                    {scan.total_vulnerabilities}개
                  </td>
                  <td className="px-4 py-4">
                    <div className="flex flex-wrap gap-1">
                      {scan.critical_count > 0 && (
                        <SeverityBadge severity={"critical" as SeverityLevel} />
                      )}
                      {scan.high_count > 0 && (
                        <SeverityBadge severity={"high" as SeverityLevel} />
                      )}
                      {scan.medium_count > 0 && (
                        <SeverityBadge severity={"medium" as SeverityLevel} />
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-4 text-xs text-slate-400 whitespace-nowrap">
                    {new Date(scan.started_at).toLocaleString("ko-KR")}
                  </td>
                </tr>
              ))}
              {scans.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-6 py-12 text-center text-slate-400">
                    스캔 기록이 없습니다. <code className="bg-slate-100 px-1 rounded">anshim scan ./프로젝트</code> 명령어로 스캔을 시작하세요.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
