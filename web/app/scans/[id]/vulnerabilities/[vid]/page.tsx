"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useState } from "react";
import { SeverityBadge } from "@/components/SeverityBadge";
import { api } from "@/lib/api";
import type { SeverityLevel, Vulnerability } from "@/lib/types";

export default function VulnerabilityDetailPage() {
  const params = useParams();
  const scanId = params.id as string;
  const vulnId = Number(params.vid);

  const [vuln, setVuln] = useState<Vulnerability | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .getVulnerability(scanId, vulnId)
      .then(setVuln)
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false));
  }, [scanId, vulnId]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-slate-500 text-sm">로딩 중...</div>
      </div>
    );
  }

  if (error || !vuln) {
    return (
      <div className="bg-red-50 border border-red-200 rounded-xl p-6 text-center">
        <p className="text-red-700 font-medium">취약점 정보를 불러올 수 없습니다</p>
        <p className="text-red-500 text-sm mt-1">{error}</p>
        <Link
          href={`/scans/${scanId}`}
          className="mt-4 inline-block text-blue-600 text-sm hover:underline"
        >
          스캔 상세로 돌아가기
        </Link>
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-4xl">
      {/* 브레드크럼 */}
      <div className="flex items-center gap-2 text-sm text-slate-400">
        <Link href="/" className="hover:text-blue-600">
          대시보드
        </Link>
        <span>/</span>
        <Link href={`/scans/${scanId}`} className="hover:text-blue-600">
          스캔 상세
        </Link>
        <span>/</span>
        <span className="text-slate-600">취약점 #{vuln.id}</span>
      </div>

      {/* 기본 정보 */}
      <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-6">
        <div className="flex items-start gap-3 mb-4">
          <SeverityBadge severity={vuln.severity as SeverityLevel} />
          {vuln.rule_id && (
            <span className="text-xs bg-slate-100 text-slate-600 px-2 py-0.5 rounded font-mono">
              {vuln.rule_id}
            </span>
          )}
        </div>
        <h1 className="text-xl font-bold text-slate-900">{vuln.title}</h1>
        {vuln.description && (
          <p className="text-slate-600 text-sm mt-2 leading-relaxed">{vuln.description}</p>
        )}

        <dl className="mt-5 grid grid-cols-2 md:grid-cols-3 gap-4 text-sm pt-4 border-t border-slate-100">
          <div>
            <dt className="text-xs text-slate-400">파일 경로</dt>
            <dd className="mt-0.5 font-mono text-xs text-slate-700 break-all">{vuln.file_path}</dd>
          </div>
          {vuln.line_start != null && (
            <div>
              <dt className="text-xs text-slate-400">라인 번호</dt>
              <dd className="mt-0.5 font-medium text-slate-700">
                {vuln.line_start}
                {vuln.line_end && vuln.line_end !== vuln.line_start && `–${vuln.line_end}`}
              </dd>
            </div>
          )}
          <div>
            <dt className="text-xs text-slate-400">분석 방법</dt>
            <dd className="mt-0.5 font-medium text-slate-700">{vuln.analysis_type}</dd>
          </div>
          <div>
            <dt className="text-xs text-slate-400">신뢰도</dt>
            <dd className="mt-0.5 font-medium text-slate-700">{vuln.confidence}%</dd>
          </div>
          <div>
            <dt className="text-xs text-slate-400">False Positive</dt>
            <dd className="mt-0.5 font-medium text-slate-700">
              {vuln.is_false_positive ? "예" : "아니오"}
            </dd>
          </div>
        </dl>
      </div>

      {/* 코드 스니펫 */}
      {vuln.code_snippet && (
        <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-6">
          <h2 className="text-base font-semibold text-slate-800 mb-3">취약한 코드</h2>
          <pre className="bg-slate-900 text-slate-100 rounded-lg p-4 text-xs overflow-x-auto leading-relaxed">
            <code>{vuln.code_snippet}</code>
          </pre>
          {vuln.line_start != null && (
            <p className="text-xs text-slate-400 mt-2">
              {vuln.file_path}:{vuln.line_start}
            </p>
          )}
        </div>
      )}

      {/* 공격 시나리오 */}
      {vuln.attack_scenario && (
        <div className="bg-orange-50 border border-orange-200 rounded-xl p-6">
          <h2 className="text-base font-semibold text-orange-800 mb-3">공격 시나리오</h2>
          <p className="text-sm text-orange-900 leading-relaxed whitespace-pre-wrap">
            {vuln.attack_scenario}
          </p>
        </div>
      )}

      {/* 수정 제안 */}
      {vuln.remediation && (
        <div className="bg-green-50 border border-green-200 rounded-xl p-6">
          <h2 className="text-base font-semibold text-green-800 mb-3">수정 제안</h2>
          <p className="text-sm text-green-900 leading-relaxed whitespace-pre-wrap">
            {vuln.remediation}
          </p>
          {vuln.remediation_code && (
            <div className="mt-4">
              <p className="text-xs font-semibold text-green-700 mb-2">수정 코드 예시</p>
              <pre className="bg-slate-900 text-green-300 rounded-lg p-4 text-xs overflow-x-auto leading-relaxed">
                <code>{vuln.remediation_code}</code>
              </pre>
            </div>
          )}
        </div>
      )}

      {/* 컴플라이언스 매핑 */}
      {vuln.compliance_mappings.length > 0 && (
        <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-6">
          <h2 className="text-base font-semibold text-slate-800 mb-4">연관 컴플라이언스 항목</h2>
          <div className="space-y-3">
            {vuln.compliance_mappings.map((m) => (
              <div
                key={m.id}
                className="flex items-start gap-3 p-3 bg-indigo-50 rounded-lg border border-indigo-100"
              >
                <span className="text-xs font-bold text-indigo-700 bg-white px-2 py-1 rounded border border-indigo-200 font-mono flex-shrink-0">
                  {m.compliance_id}
                </span>
                <div>
                  <p className="text-sm font-medium text-indigo-900">
                    {m.compliance_title ?? m.compliance_id}
                  </p>
                  {m.compliance_category && (
                    <p className="text-xs text-indigo-600 mt-0.5">{m.compliance_category}</p>
                  )}
                  {m.notes && (
                    <p className="text-xs text-slate-600 mt-1.5">{m.notes}</p>
                  )}
                </div>
                <span className="ml-auto text-xs text-indigo-500 uppercase font-medium flex-shrink-0">
                  {m.compliance_type}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="pb-8">
        <Link
          href={`/scans/${scanId}`}
          className="text-sm text-blue-600 hover:text-blue-800 hover:underline"
        >
          ← 스캔 상세로 돌아가기
        </Link>
      </div>
    </div>
  );
}
