"use client";

import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

interface ComplianceItem {
  category: string;
  count: number;
}

interface Props {
  data: ComplianceItem[];
  title?: string;
}

const COLORS = ["#3b82f6", "#6366f1", "#8b5cf6", "#a855f7", "#ec4899", "#f43f5e"];

export function ComplianceChart({ data, title = "컴플라이언스 항목별 취약점" }: Props) {
  if (!data || data.length === 0) {
    return (
      <div className="flex items-center justify-center h-40 text-gray-400">
        데이터 없음
      </div>
    );
  }

  return (
    <div className="w-full">
      {title && <h3 className="text-sm font-medium text-gray-700 mb-3">{title}</h3>}
      <ResponsiveContainer width="100%" height={250}>
        <BarChart data={data} layout="vertical" margin={{ left: 20, right: 30 }}>
          <CartesianGrid strokeDasharray="3 3" horizontal={false} />
          <XAxis type="number" tick={{ fontSize: 12 }} />
          <YAxis type="category" dataKey="category" tick={{ fontSize: 11 }} width={100} />
          <Tooltip
            formatter={(value: number) => [`${value}개`, "취약점"]}
            labelStyle={{ fontWeight: "bold" }}
          />
          <Bar dataKey="count" radius={[0, 4, 4, 0]}>
            {data.map((_, idx) => (
              <Cell key={idx} fill={COLORS[idx % COLORS.length]} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
