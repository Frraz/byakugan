/** Vulnerabilities — placeholder da Fase 3 (Vulnerability Assessment). */

import { PageHeader } from "../components/PageHeader";
import { EmptyState } from "../components/ui";

export function VulnerabilitiesPage() {
  return (
    <div>
      <PageHeader
        title="Vulnerabilities"
        description="Correlação de findings com a base CVE/CVSS."
      />
      <EmptyState
        title="Fase 3 — em breve"
        hint="O Vulnerability Assessment será entregue na próxima fase do roadmap."
      />
    </div>
  );
}
