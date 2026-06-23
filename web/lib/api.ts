import type { Scan, ScanDetail, ScanListResponse, Stats, Vulnerability } from "./types";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

async function fetchJson<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: { "Content-Type": "application/json", ...(options?.headers ?? {}) },
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`API 오류 ${res.status}: ${text}`);
  }
  return res.json() as Promise<T>;
}

export const api = {
  getStats(): Promise<Stats> {
    return fetchJson<Stats>("/api/stats");
  },

  listScans(limit = 20, offset = 0): Promise<ScanListResponse> {
    return fetchJson<ScanListResponse>(`/api/scans?limit=${limit}&offset=${offset}`);
  },

  getScan(scanId: string): Promise<ScanDetail> {
    return fetchJson<ScanDetail>(`/api/scans/${scanId}`);
  },

  listVulnerabilities(
    scanId: string,
    severity?: string,
    limit = 200,
    offset = 0
  ): Promise<Vulnerability[]> {
    const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
    if (severity) params.set("severity", severity);
    return fetchJson<Vulnerability[]>(`/api/scans/${scanId}/vulnerabilities?${params}`);
  },

  getVulnerability(scanId: string, vulnId: number): Promise<Vulnerability> {
    return fetchJson<Vulnerability>(`/api/scans/${scanId}/vulnerabilities/${vulnId}`);
  },

  deleteScan(scanId: string): Promise<{ message: string }> {
    return fetchJson<{ message: string }>(`/api/scans/${scanId}`, { method: "DELETE" });
  },
};
