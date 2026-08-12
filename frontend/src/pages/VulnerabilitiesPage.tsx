/** Vulnerabilities — findings do ambiente, correlacionados com CVEs (RF008). */

import { useState } from "react";
import { Link } from "react-router-dom";

import { PageHeader } from "../components/PageHeader";
import {
  EmptyState,
  ErrorBanner,
  Field,
  Select,
  SeverityBadge,
  Skeleton,
  Table,
  Td,
  Th,
} from "../components/ui";
import { useFindings } from "../hooks/useData";
import type { Severity } from "../lib/types";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export function VulnerabilitiesPage() {
  const [severity, setSeverity] = useState("");
  const findings = useFindings(severity ? { severity } : undefined);
  const results = findings.data?.results ?? [];

  return (
    <div>
      <PageHeader
        title="Vulnerabilities"
        description="Findings do ambiente, correlacionados com a base CVE/CVSS (NVD)."
      />

      <div className="mb-4 max-w-xs">
        <Field label="Severidade">
          <Select value={severity} onChange={(e) => setSeverity(e.target.value)}>
            <option value="">Todas</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s} className="capitalize">
                {s}
              </option>
            ))}
          </Select>
        </Field>
      </div>

      {findings.isLoading ? (
        <Skeleton className="h-40 w-full" />
      ) : findings.isError ? (
        <ErrorBanner message="Não foi possível carregar os findings." />
      ) : results.length === 0 ? (
        <EmptyState
          title="Nenhum finding"
          hint="Execute um scan de vulnerability (ou full) sobre um alvo já mapeado para correlacionar CVEs conhecidos."
        />
      ) : (
        <Table>
          <thead>
            <tr>
              <Th>Finding</Th>
              <Th>Severidade</Th>
              <Th>CVSS</Th>
              <Th>Categoria</Th>
              <Th>Ativo</Th>
              <Th>Detectado</Th>
            </tr>
          </thead>
          <tbody>
            {results.map((f) => (
              <tr key={f.id} className="hover:bg-white/5">
                <Td className="max-w-md">
                  <p className="font-medium text-foreground">{f.title}</p>
                  <p className="mt-0.5 truncate text-xs text-muted">{f.recommendation}</p>
                </Td>
                <Td>
                  <SeverityBadge severity={f.severity} />
                </Td>
                <Td className="font-mono text-primary">{f.cvss ?? "—"}</Td>
                <Td className="text-muted">{f.category}</Td>
                <Td>
                  <Link
                    to={`/assets/${f.asset}`}
                    className="font-mono text-xs text-primary hover:underline"
                  >
                    {f.asset.slice(0, 8)}…
                  </Link>
                </Td>
                <Td className="text-muted">{new Date(f.created_at).toLocaleString("pt-BR")}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </div>
  );
}
