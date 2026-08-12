/** Assets — inventário descoberto (RF007), com busca. */

import { useState } from "react";
import { Link } from "react-router-dom";

import { PageHeader } from "../components/PageHeader";
import { EmptyState, Input, Skeleton, Table, Td, Th } from "../components/ui";
import { useAssets } from "../hooks/useData";

export function AssetsPage() {
  const [search, setSearch] = useState("");
  const { data, isLoading } = useAssets(search || undefined);
  const assets = data?.results ?? [];

  return (
    <div>
      <PageHeader
        title="Assets"
        description="Inventário de ativos descobertos pelos scans."
        actions={
          <Input
            className="w-64"
            placeholder="Buscar IP / host / domínio…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        }
      />

      {isLoading ? (
        <Skeleton className="h-40 w-full" />
      ) : assets.length === 0 ? (
        <EmptyState title="Nenhum ativo" hint="Execute um scan de descoberta para popular o inventário." />
      ) : (
        <Table>
          <thead>
            <tr>
              <Th>IP</Th>
              <Th>Hostname</Th>
              <Th>Domínio</Th>
              <Th>SO</Th>
              <Th>Status</Th>
            </tr>
          </thead>
          <tbody>
            {assets.map((a) => (
              <tr key={a.id} className="hover:bg-white/5">
                <Td className="font-mono text-primary">
                  <Link to={`/assets/${a.id}`} className="hover:underline">
                    {a.ip ?? "—"}
                  </Link>
                </Td>
                <Td>{a.hostname ?? "—"}</Td>
                <Td className="text-muted">{a.domain ?? "—"}</Td>
                <Td className="text-muted">{a.os ?? "—"}</Td>
                <Td className="capitalize">{a.status}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </div>
  );
}
