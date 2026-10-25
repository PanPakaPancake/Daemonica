import { useMemo, useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Icon } from "./icons";
import { useContextMenu, type MenuItem } from "./Modal";

/** Filter kinds: text = contains; number/bytes = comparison or range
 * (">10", "<=1M", "1K-2M"); date = changed within/older than (age options);
 * options = exact match. */
export type FilterKind = "text" | "number" | "bytes" | "date" | { options: { value: string; label: string }[] };

/** A column of a DataTable. A column is sortable when it has sortValue. It
 * is filterable when it has filter, or by default when it has sortValue
 * (kind inferred from the values); filter: false turns that off. */
export interface Column<T> {
  key: string;
  label: string;
  cell: (row: T) => ReactNode;
  sortValue?: (row: T) => string | number | boolean | null | undefined;
  /** Text matched by a text filter; defaults to sortValue. */
  filterValue?: (row: T) => string;
  filter?: FilterKind | false;
  thClass?: string;
  tdClass?: string;
  /** Tooltip of the cell (e.g. the full text of a truncated cell). */
  tdTitle?: (row: T) => string;
  /** Hide the header label (e.g. an actions column). */
  srOnly?: boolean;
}

export interface SortState {
  key: string;
  desc: boolean;
}

export type Filters = Record<string, string>;

const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: "base" });

function cmp(a: unknown, b: unknown): number {
  const ae = a === undefined || a === null || a === "";
  const be = b === undefined || b === null || b === "";
  if (ae || be) return ae === be ? 0 : ae ? 1 : -1; // empty values last
  if (typeof a === "number" && typeof b === "number") return a - b;
  if (typeof a === "boolean" && typeof b === "boolean") return Number(a) - Number(b);
  return collator.compare(String(a), String(b));
}

function textOf<T>(c: Column<T>, row: T): string {
  if (c.filterValue) return c.filterValue(row);
  const v = c.sortValue?.(row);
  return v === undefined || v === null ? "" : String(v);
}

const isoDate = /^\d{4}-\d{2}-\d{2}T/;

/** The filter kind of a column (explicit, or inferred from the first value). */
export function filterKind<T>(c: Column<T>, rows: T[]): FilterKind | null {
  if (c.filter === false) return null;
  if (c.filter) return c.filter;
  if (!c.sortValue) return null;
  for (const r of rows) {
    const v = c.sortValue(r);
    if (v === undefined || v === null || v === "") continue;
    if (typeof v === "number") return "number";
    if (typeof v === "string" && isoDate.test(v)) return "date";
    return "text";
  }
  return "text";
}

export interface NumRange {
  min: number;
  max: number;
}

function parseNum(s: string, units: boolean): number | null {
  let l = s.toLowerCase().replace(",", ".");
  let mul = 1;
  if (units) {
    l = l.replace(/i?b$/, "");
    const i = "kmgt".indexOf(l.slice(-1));
    if (l && i >= 0) {
      mul = 1024 ** (i + 1);
      l = l.slice(0, -1);
    }
  }
  if (!/^\d+(\.\d+)?$/.test(l)) return null;
  return Number(l) * mul;
}

/** Parses ">10", "<=1.5M", "=0", "1K-2M" or "10" (= at least 10); null if invalid. Same grammar as the server's files.ParseNumFilter. */
export function parseNumFilter(s: string, units = false): NumRange | null {
  const f = s.replace(/\s+/g, "");
  if (!f) return null;
  const range = /^([^<>=-][^-]*)-(.+)$/.exec(f);
  if (range) {
    const lo = parseNum(range[1] ?? "", units);
    const hi = parseNum(range[2] ?? "", units);
    return lo !== null && hi !== null && lo <= hi ? { min: lo, max: hi } : null;
  }
  const op = /^(>=|<=|>|<|=)/.exec(f)?.[1] ?? "";
  const n = parseNum(f.slice(op.length), units);
  if (n === null) return null;
  switch (op) {
    case ">":
      return { min: n + 1e-9, max: Infinity };
    case "<":
      return { min: -Infinity, max: n - 1e-9 };
    case "<=":
      return { min: -Infinity, max: n };
    case "=":
      return { min: n, max: n };
  }
  return { min: n, max: Infinity };
}

/** Age filter values: changed within n days, or ("-") older than n days. */
export const ageOptions = ["1d", "7d", "30d", "365d", "-30d", "-365d"] as const;

function ageMatch(v: unknown, f: string, now: number): boolean {
  const t = typeof v === "number" ? v : Date.parse(String(v ?? ""));
  if (!Number.isFinite(t)) return false;
  const days = Number(f.replace(/^-/, "").replace(/d$/, ""));
  const cutoff = now - days * 86_400_000;
  return f.startsWith("-") ? t < cutoff : t >= cutoff;
}

/** Whether a (non-empty) filter value is usable, e.g. to mark an input invalid. */
export function filterValid(kind: FilterKind | null, f: string): boolean {
  if (!f.trim() || (kind !== "number" && kind !== "bytes")) return true;
  return parseNumFilter(f, kind === "bytes") !== null;
}

/** Sorts and filters rows client-side (stable; empty values last). Invalid number filters are ignored. */
export function applyTable<T>(rows: T[], columns: Column<T>[], sort: SortState | null, filters: Filters): T[] {
  const now = Date.now();
  const active = columns
    .map((c) => ({ c, kind: filterKind(c, rows), f: (filters[c.key] ?? "").trim() }))
    .filter(({ kind, f }) => kind && f !== "" && filterValid(kind, f));
  let out = active.length
    ? rows.filter((r) =>
        active.every(({ c, kind, f }) => {
          if (kind === "number" || kind === "bytes") {
            const range = parseNumFilter(f, kind === "bytes");
            if (!range) return true;
            const raw = c.sortValue?.(r);
            const n = typeof raw === "number" ? raw : Number(textOf(c, r));
            return textOf(c, r) !== "" && Number.isFinite(n) && n >= range.min && n <= range.max;
          }
          if (kind === "date") return ageMatch(c.sortValue?.(r), f, now);
          const v = textOf(c, r);
          return kind === "text" ? v.toLowerCase().includes(f.toLowerCase()) : v === f;
        }),
      )
    : rows;
  const col = sort && columns.find((c) => c.key === sort.key && c.sortValue);
  if (col?.sortValue && sort) {
    const get = col.sortValue;
    out = out
      .map((r, i) => ({ r, i, v: get(r) }))
      .sort((x, y) => {
        const empty = (v: unknown) => v === undefined || v === null || v === "";
        if (empty(x.v) !== empty(y.v)) return empty(x.v) ? 1 : -1; // empty last in both directions
        return (sort.desc ? -cmp(x.v, y.v) : cmp(x.v, y.v)) || x.i - y.i;
      })
      .map((x) => x.r);
  }
  return out;
}

/**
 * Table with sortable column headers and a filter row (toggled with the
 * funnel button in a header). Uncontrolled by default (sorts and filters the
 * given rows); pass sort/onSort and filters/onFilters to let a server do it.
 */
export function DataTable<T>({
  columns,
  rows,
  rowKey,
  defaultSort = null,
  sort: sortProp,
  onSort,
  filters: filtersProp,
  onFilters,
  loading,
  empty,
  rowClass,
  onRowClick,
  className = "min-w-[640px]",
  footer,
  label,
  stickyHeader,
  rowMenu,
}: {
  columns: Column<T>[];
  rows: T[] | null | undefined;
  rowKey: (row: T) => string;
  defaultSort?: SortState | null;
  sort?: SortState | null;
  onSort?: (s: SortState | null) => void;
  filters?: Filters;
  onFilters?: (f: Filters) => void;
  loading?: boolean;
  empty?: ReactNode;
  rowClass?: (row: T) => string;
  onRowClick?: (row: T) => void;
  className?: string;
  footer?: ReactNode;
  label?: string;
  /** Keep the header visible in a scrolling container. */
  stickyHeader?: boolean;
  /** Right-click menu of a row (usually the same actions as its buttons or ⋯ menu). */
  rowMenu?: (row: T) => { label: string; items: MenuItem[] };
}) {
  const { t } = useTranslation();
  const [sortState, setSortState] = useState<SortState | null>(defaultSort);
  const [filterState, setFilterState] = useState<Filters>({});
  const [showFilters, setShowFilters] = useState(false);
  const controlled = onSort !== undefined;
  const sort = controlled ? (sortProp ?? null) : sortState;
  const filters = useMemo(() => (onFilters ? (filtersProp ?? {}) : filterState), [onFilters, filtersProp, filterState]);
  const setSort = controlled ? onSort : setSortState;
  const setFilters = onFilters ?? setFilterState;
  const ctx = useContextMenu();
  const kinds = useMemo(() => new Map(columns.map((c) => [c.key, filterKind(c, rows ?? [])])), [columns, rows]);
  const hasFilters = [...kinds.values()].some(Boolean);
  const activeFilters = Object.entries(filters).filter(([k, v]) => v !== "" && kinds.get(k)).length;

  const shown = useMemo(
    () => (controlled && onFilters ? (rows ?? []) : applyTable(rows ?? [], columns, controlled ? null : sort, onFilters ? {} : filters)),
    [rows, columns, sort, filters, controlled, onFilters],
  );

  const toggleSort = (key: string) => {
    if (sort?.key !== key) setSort({ key, desc: false });
    else if (!sort.desc) setSort({ key, desc: true });
    else setSort(defaultSort);
  };
  const setFilter = (key: string, v: string) => setFilters({ ...filters, [key]: v });
  // The funnel sits in the first filterable column's header.
  const funnelAt = columns.find((c) => kinds.get(c.key))?.key;

  return (
    <>
      <table className={`w-full text-left text-sm ${className}`} aria-label={label}>
        <thead className={`text-xs uppercase tracking-wide text-faint ${stickyHeader ? "sticky top-0 z-10 bg-bg-1" : ""}`}>
          <tr>
            {columns.map((c) => {
              const active = sort?.key === c.key;
              return (
                <th
                  key={c.key}
                  scope="col"
                  className={`px-3 py-2 font-semibold ${c.thClass ?? ""}`}
                  aria-sort={c.sortValue ? (active ? (sort?.desc ? "descending" : "ascending") : "none") : undefined}
                >
                  <span className={`inline-flex items-center gap-1 ${c.thClass?.includes("text-right") ? "flex-row-reverse" : ""}`}>
                    {c.srOnly ? (
                      <span className="sr-only">{c.label}</span>
                    ) : c.sortValue ? (
                      <button
                        type="button"
                        className="inline-flex items-center gap-1 uppercase hover:text-fg"
                        onClick={() => toggleSort(c.key)}
                        title={t("table.sortBy", { col: c.label })}
                      >
                        {c.label}
                        <span aria-hidden="true" className={active ? "text-violet" : "opacity-40"}>
                          {active ? (sort?.desc ? "▼" : "▲") : "↕"}
                        </span>
                      </button>
                    ) : (
                      c.label
                    )}
                    {hasFilters && c.key === funnelAt && (
                      <button
                        type="button"
                        className={`relative rounded p-0.5 hover:text-fg ${showFilters || activeFilters ? "text-violet" : ""}`}
                        aria-expanded={showFilters}
                        title={t("table.filters")}
                        onClick={() => setShowFilters(!showFilters)}
                      >
                        <Icon name="filter" className="h-3.5 w-3.5" />
                        <span className="sr-only">{t("table.filters")}</span>
                        {activeFilters > 0 && (
                          <span className="absolute -right-1.5 -top-1.5 rounded-full bg-violet px-1 text-[9px] leading-[14px] text-white">{activeFilters}</span>
                        )}
                      </button>
                    )}
                  </span>
                </th>
              );
            })}
          </tr>
          {showFilters && (
            <tr className="normal-case tracking-normal">
              {columns.map((c) => {
                const kind = kinds.get(c.key) ?? null;
                const v = filters[c.key] ?? "";
                const aria = t("table.filterBy", { col: c.label });
                return (
                  <th key={c.key} className="px-2 pb-2 font-normal">
                    {(kind === "text" || kind === "number" || kind === "bytes") && (
                      <input
                        className={`input min-h-8 w-full min-w-16 px-2 py-1 text-xs ${filterValid(kind, v) ? "" : "border-bad"}`}
                        value={v}
                        onChange={(e) => setFilter(c.key, e.target.value)}
                        placeholder={kind === "text" ? t("table.filter") : t(kind === "bytes" ? "table.filterBytes" : "table.filterNumber")}
                        title={kind === "text" ? undefined : t("table.numberHelp")}
                        aria-label={aria}
                        aria-invalid={!filterValid(kind, v)}
                        inputMode={kind === "number" ? "decimal" : undefined}
                      />
                    )}
                    {kind && typeof kind === "object" && (
                      <select
                        className="input min-h-8 w-full min-w-16 px-1 py-1 text-xs"
                        value={v}
                        onChange={(e) => setFilter(c.key, e.target.value)}
                        aria-label={aria}
                      >
                        <option value="">{t("table.all")}</option>
                        {kind.options.map((o) => (
                          <option key={o.value} value={o.value}>
                            {o.label}
                          </option>
                        ))}
                      </select>
                    )}
                    {kind === "date" && (
                      <select
                        className="input min-h-8 w-full min-w-16 px-1 py-1 text-xs"
                        value={v}
                        onChange={(e) => setFilter(c.key, e.target.value)}
                        aria-label={aria}
                      >
                        <option value="">{t("table.all")}</option>
                        {ageOptions.map((o) => (
                          <option key={o} value={o}>
                            {t(`table.age.${o}`)}
                          </option>
                        ))}
                      </select>
                    )}
                    {!kind && columns.indexOf(c) === columns.length - 1 && activeFilters > 0 && (
                      <button type="button" className="rounded p-1 text-muted hover:text-fg" title={t("table.reset")} onClick={() => setFilters({})}>
                        <Icon name="close" className="h-4 w-4" />
                        <span className="sr-only">{t("table.reset")}</span>
                      </button>
                    )}
                  </th>
                );
              })}
            </tr>
          )}
        </thead>
        <tbody>
          {loading && !rows && (
            <tr>
              <td colSpan={columns.length} className="px-3 py-6 text-muted">
                {t("common.loading")}
              </td>
            </tr>
          )}
          {rows && shown.length === 0 && (
            <tr>
              <td colSpan={columns.length} className="px-3 py-6 text-muted">
                {activeFilters > 0 && rows.length > 0 ? t("table.noMatch") : (empty ?? t("table.empty"))}
              </td>
            </tr>
          )}
          {shown.map((r) => (
            <tr
              key={rowKey(r)}
              className={`border-t border-line hover:bg-bg-2/50 ${onRowClick ? "cursor-pointer" : ""} ${rowClass?.(r) ?? ""}`}
              onClick={onRowClick ? () => onRowClick(r) : undefined}
              onContextMenu={
                rowMenu
                  ? (e) => {
                      const m = rowMenu(r);
                      ctx.onContextMenu(e, m.label, m.items);
                    }
                  : undefined
              }
            >
              {columns.map((c) => (
                <td key={c.key} className={`px-3 py-1.5 ${c.tdClass ?? ""}`} title={c.tdTitle?.(r)}>
                  {c.cell(r)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
        {footer && (
          <tfoot>
            <tr>
              <td colSpan={columns.length}>{footer}</td>
            </tr>
          </tfoot>
        )}
      </table>
      {ctx.menu}
    </>
  );
}
