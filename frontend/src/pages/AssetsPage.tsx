/** Assets — inventário de ativos descobertos (RF007), com busca e paginação. */

import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Boxes, Search } from "lucide-react";

import { PageHeader } from "@/components/PageHeader";
import { DataPagination } from "@/components/ui/data-pagination";
import { EmptyState } from "@/components/ui/empty-state";
import { ErrorBanner } from "@/components/ui/error-banner";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { TableSkeleton } from "@/components/ui/table-skeleton";
import { useAssets } from "@/hooks/useData";
import { useDebounce } from "@/hooks/useDebounce";
import { usePageTitle } from "@/hooks/usePageTitle";
import { errorMessage } from "@/lib/errors";

export function AssetsPage() {
  usePageTitle("Assets");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const debounced = useDebounce(search);

  const params = useMemo(() => ({ search: debounced || undefined, page }), [debounced, page]);
  const { data, isLoading, isError, error } = useAssets(params);
  const assets = data?.results ?? [];

  return (
    <div>
      <PageHeader
        title="Assets"
        description="Inventário de ativos descobertos pelos scans."
      />

      <div className="relative mb-4 max-w-md">
        <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          className="pl-9"
          placeholder="Buscar IP / host / domínio…"
          value={search}
          onChange={(e) => {
            setSearch(e.target.value);
            setPage(1);
          }}
        />
      </div>

      {isError ? (
        <ErrorBanner message={errorMessage(error)} />
      ) : isLoading ? (
        <TableSkeleton columns={5} />
      ) : assets.length === 0 ? (
        <EmptyState
          icon={Boxes}
          title="Nenhum ativo"
          hint="Execute um scan de descoberta para popular o inventário."
        />
      ) : (
        <div className="space-y-4">
          <div className="glass overflow-x-auto p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>IP</TableHead>
                  <TableHead>Hostname</TableHead>
                  <TableHead>Domínio</TableHead>
                  <TableHead>SO</TableHead>
                  <TableHead>Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {assets.map((a) => (
                  <TableRow key={a.id}>
                    <TableCell className="font-mono text-primary">
                      <Link to={`/assets/${a.id}`} className="hover:underline">
                        {a.ip ?? "—"}
                      </Link>
                    </TableCell>
                    <TableCell>{a.hostname ?? "—"}</TableCell>
                    <TableCell className="text-muted-foreground">{a.domain ?? "—"}</TableCell>
                    <TableCell className="text-muted-foreground">{a.os ?? "—"}</TableCell>
                    <TableCell>
                      <span
                        className={
                          a.status === "active"
                            ? "inline-flex items-center gap-1.5 text-sm text-success"
                            : "inline-flex items-center gap-1.5 text-sm text-muted-foreground"
                        }
                      >
                        <span className="h-1.5 w-1.5 rounded-full bg-current" />
                        {a.status === "active" ? "Ativo" : "Inativo"}
                      </span>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
          <DataPagination count={data?.count ?? 0} page={page} onPageChange={setPage} />
        </div>
      )}
    </div>
  );
}
