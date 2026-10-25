import { useMemo, useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Icon } from "./icons";

/** A column of a DataTable. A column is sortable when it has sortValue and
 * filterable when it has filter (text: "contains", options: exact match). */
export interface Column<T> {
  key: string;
  label: string;
  cell: (row: T) => ReactNode;
  sortValue?: (row: T) => string | number | boolean | null | undefined;
  /** Text matched by the filter; defaults to sortValue. */
  filterValue?: (row: T) => string;
  filter?: "text" | { options: { value: string; label: string }[] };
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

/** Sorts and filters rows client-side (stable; empty values last). */
export function applyTable<T>(rows: T[], columns: Column<T>[], sort: SortState | null, filters: Filters): T[] {
  const active = columns.filter((c) => c.filter && (filters[c.key] ?? "") !== "");
  let out = active.length
    ? rows.filter((r) =>
        active.every((c) => {
          const f = filters[c.key] ?? "";
          const v = textOf(c, r);
          return c.filter === "text" ? v.toLowerCase().includes(f.toLowerCase()) : v === f;
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
  const hasFilters = columns.some((c) => c.filter);
  const activeFilters = Object.values(filters).filter((v) => v !== "").length;

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
  const funnelAt = columns.find((c) => c.filter)?.key;

  return (
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
                      <span aria-hidden="true" className={active ? "" : "opacity-0"}>
                        {active && sort?.desc ? "▼" : "▲"}
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
            {columns.map((c, i) => (
              <th key={c.key} className="px-2 pb-2 font-normal">
                {c.filter === "text" && (
                  <input
                    className="input min-h-8 w-full min-w-16 px-2 py-1 text-xs"
                    value={filters[c.key] ?? ""}
                    onChange={(e) => setFilter(c.key, e.target.value)}
                    placeholder={t("table.filter")}
                    aria-label={t("table.filterBy", { col: c.label })}
                  />
                )}
                {c.filter && c.filter !== "text" && (
                  <select
                    className="input min-h-8 w-full min-w-16 px-1 py-1 text-xs"
                    value={filters[c.key] ?? ""}
                    onChange={(e) => setFilter(c.key, e.target.value)}
                    aria-label={t("table.filterBy", { col: c.label })}
                  >
                    <option value="">{t("table.all")}</option>
                    {c.filter.options.map((o) => (
                      <option key={o.value} value={o.value}>
                        {o.label}
                      </option>
                    ))}
                  </select>
                )}
                {i === columns.length - 1 && !c.filter && activeFilters > 0 && (
                  <button type="button" className="text-xs text-muted underline hover:text-fg" onClick={() => setFilters({})}>
                    {t("table.reset")}
                  </button>
                )}
              </th>
            ))}
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
  );
}
