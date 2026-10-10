import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { ExploitationPlaybook } from "@/lib/types";
import { EvidencePlaybookCard, interpolate } from "../EvidencePlaybookCard";

function _playbook(overrides: Partial<ExploitationPlaybook> = {}): ExploitationPlaybook {
  return {
    id: "1",
    key: "injection.sqli-error",
    title: "Possível SQL injection",
    category: "injection",
    vuln_class: "SQL Injection",
    summary: "...",
    prerequisites: "",
    steps: [],
    escalation_path: [],
    max_impact: "db-read",
    tools: [],
    references: [],
    detection_rule: "",
    created_at: "",
    updated_at: "",
    ...overrides,
  };
}

describe("interpolate", () => {
  it("substitutes {url}/{param}/{host} placeholders with context", () => {
    expect(interpolate("curl {url}", { url: "https://t/x" })).toBe("curl https://t/x");
    expect(interpolate("{param}=1", {})).toBe("{param}=1");
  });
});

describe("EvidencePlaybookCard — regra de detecção (Sigma)", () => {
  it("renders the detection rule section when detection_rule is present", () => {
    render(
      <EvidencePlaybookCard
        playbook={_playbook({ detection_rule: "title: SQL Injection\nid: abc\nlevel: high\n" })}
      />,
    );
    expect(screen.getByText(/Regra de detecção \(Sigma\)/i)).toBeInTheDocument();
    expect(screen.getByText(/title: SQL Injection/)).toBeInTheDocument();
  });

  it("omits the detection rule section when detection_rule is empty", () => {
    render(<EvidencePlaybookCard playbook={_playbook({ detection_rule: "" })} />);
    expect(screen.queryByText(/Regra de detecção \(Sigma\)/i)).not.toBeInTheDocument();
  });
});
