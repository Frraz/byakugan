/** Helpers de formatação (datas, tamanhos, durações) — pt-BR, sem dependências. */

const DATE = new Intl.DateTimeFormat("pt-BR", { dateStyle: "medium" });
const DATE_TIME = new Intl.DateTimeFormat("pt-BR", { dateStyle: "medium", timeStyle: "short" });
const RELATIVE = new Intl.RelativeTimeFormat("pt-BR", { numeric: "auto" });

type DateInput = string | number | Date | null | undefined;

function toDate(value: DateInput): Date | null {
  if (!value) return null;
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

/** Data curta (ex.: "12 de ago. de 2026"). */
export function formatDate(value: DateInput): string {
  const date = toDate(value);
  return date ? DATE.format(date) : "—";
}

/** Data e hora (ex.: "12 de ago. de 2026 14:30"). */
export function formatDateTime(value: DateInput): string {
  const date = toDate(value);
  return date ? DATE_TIME.format(date) : "—";
}

const UNITS: [Intl.RelativeTimeFormatUnit, number][] = [
  ["year", 31536000],
  ["month", 2592000],
  ["day", 86400],
  ["hour", 3600],
  ["minute", 60],
  ["second", 1],
];

/** Tempo relativo ao agora (ex.: "há 3 horas"). */
export function formatRelative(value: DateInput): string {
  const date = toDate(value);
  if (!date) return "—";
  const seconds = Math.round((date.getTime() - Date.now()) / 1000);
  const abs = Math.abs(seconds);
  for (const [unit, secs] of UNITS) {
    if (abs >= secs || unit === "second") {
      return RELATIVE.format(Math.round(seconds / secs), unit);
    }
  }
  return RELATIVE.format(0, "second");
}

/** Tamanho de arquivo legível (ex.: "24 KB"). */
export function formatBytes(bytes: number | null | undefined): string {
  if (bytes == null || Number.isNaN(bytes)) return "—";
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(value >= 10 || Number.isInteger(value) ? 0 : 1)} ${units[unit]}`;
}

/** Duração entre dois instantes (ex.: "2 min 13 s"). */
export function formatDuration(start: DateInput, end: DateInput): string {
  const from = toDate(start);
  const to = toDate(end);
  if (!from || !to) return "—";
  let seconds = Math.max(0, Math.round((to.getTime() - from.getTime()) / 1000));
  if (seconds < 60) return `${seconds} s`;
  const hours = Math.floor(seconds / 3600);
  seconds %= 3600;
  const minutes = Math.floor(seconds / 60);
  seconds %= 60;
  const parts = [];
  if (hours) parts.push(`${hours} h`);
  if (minutes) parts.push(`${minutes} min`);
  if (seconds && !hours) parts.push(`${seconds} s`);
  return parts.join(" ") || "0 s";
}
