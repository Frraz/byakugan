/** Inventário observado pelos scans; não representa disponibilidade em tempo real. */
import { Link } from "react-router-dom";
import { Server } from "lucide-react";
import { PageHeader } from "@/components/PageHeader";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { DataPagination } from "@/components/ui/data-pagination";
import { EmptyState } from "@/components/ui/empty-state";
import { ErrorBanner } from "@/components/ui/error-banner";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { TableSkeleton } from "@/components/ui/table-skeleton";
import { useAssets } from "@/hooks/useData";
import { useDebounce } from "@/hooks/useDebounce";
import { useUrlState } from "@/hooks/useUrlState";
import { usePageTitle } from "@/hooks/usePageTitle";
import { errorMessage } from "@/lib/errors";
import { formatDateTime } from "@/lib/format";

export function AssetsPage() {
  usePageTitle("Inventário de ativos");
  const [search, setSearch] = useUrlState<string>("search", "");
  const [page, setPage] = useUrlState<number>("page", 1);
  const debounced = useDebounce(search);
  const assets = useAssets({ search: debounced || undefined, page });
  return <div>
    <PageHeader title="Inventário de ativos" description="Hosts e serviços registrados pelas análises. As observações históricas não confirmam disponibilidade atual." />
    <Input className="mb-5 max-w-md" aria-label="Buscar ativos por IP, hostname ou domínio" placeholder="Buscar por IP, hostname ou domínio…" value={search} onChange={(event) => { setSearch(event.target.value); setPage(1); }} />
    {assets.isError ? <ErrorBanner message={errorMessage(assets.error)} onRetry={() => void assets.refetch()} /> : assets.isLoading ? <TableSkeleton columns={4} /> : !assets.data?.results.length ? <EmptyState icon={Server} title={search ? "Nenhum ativo encontrado" : "Nenhum ativo observado"} hint={search ? "Ajuste a busca para encontrar outros registros." : "Os ativos aparecem após a descoberta por um scan autorizado."} action={search ? <Button variant="outline" onClick={() => { setSearch(""); setPage(1); }}>Limpar busca</Button> : <Button asChild variant="outline"><Link to="/scans">Ver scans</Link></Button>} /> : <>
      <div className="glass overflow-hidden"><Table>
        <TableHeader><TableRow><TableHead>Ativo</TableHead><TableHead>IP</TableHead><TableHead>Findings</TableHead><TableHead>Registrado em</TableHead></TableRow></TableHeader>
        <TableBody>{assets.data.results.map((asset) => <TableRow key={asset.id}>
          <TableCell><Link className="block max-w-sm break-all font-medium text-primary hover:underline" to={`/assets/${asset.id}`}>{asset.hostname || asset.domain || asset.ip || asset.id}</Link><p className="mt-1 max-w-sm break-words text-xs text-muted-foreground">{asset.os || "Sistema operacional não observado"}</p></TableCell>
          <TableCell className="font-mono text-xs">{asset.ip || "Não observado"}</TableCell>
          <TableCell className="tabular-nums">{asset.findings_count}</TableCell>
          <TableCell className="whitespace-nowrap text-xs text-muted-foreground">{formatDateTime(asset.created_at)}</TableCell>
        </TableRow>)}</TableBody>
      </Table></div>
      <div className="mt-4"><DataPagination count={assets.data.count} page={page} onPageChange={setPage} /></div>
    </>}
  </div>;
}
