/** Render a simple left-aligned text table. */
export function renderTable(headers: string[], rows: string[][]): string {
  const widths = headers.map((h, i) =>
    Math.max(h.length, ...rows.map((r) => (r[i] ?? "").length))
  );
  const line = (cells: string[]): string =>
    cells.map((c, i) => c.padEnd(widths[i] ?? 0)).join("  ").trimEnd();
  const out = [line(headers), line(widths.map((w) => "-".repeat(w)))];
  for (const row of rows) out.push(line(row));
  return out.join("\n");
}

export function truncate(value: string, max: number): string {
  if (value.length <= max) return value;
  return value.slice(0, Math.max(0, max - 3)) + "...";
}

export function shortId(id: string): string {
  return id.length > 8 ? id.slice(0, 8) : id;
}

export function formatDate(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toISOString().replace("T", " ").slice(0, 16);
}
