import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { categoryLabel } from "../ui/category-badge";
import { SeverityBadge } from "../ui/severity-badge";
import { StatusBadge } from "../ui/status-badge";

describe("SeverityBadge", () => {
  it("renders the localized severity label and aria-label", () => {
    render(<SeverityBadge severity="critical" />);
    const badge = screen.getByLabelText("Severidade Crítica");
    expect(badge).toBeInTheDocument();
    expect(badge).toHaveTextContent(/crítica/i);
  });
});

describe("StatusBadge", () => {
  it("maps scan status to a localized label", () => {
    render(<StatusBadge status="running" />);
    expect(screen.getByText("Executando")).toBeInTheDocument();
  });
});

describe("categoryLabel", () => {
  it("translates every backend FindingCategory to a PT-BR label (no raw fallback)", () => {
    // Espelha apps.scans.models.FindingCategory — se o backend ganhar uma
    // categoria nova sem o frontend ser atualizado, este teste quebra em vez
    // de deixar a UI silenciosamente mostrar o valor bruto em inglês.
    const backendCategories = [
      "software",
      "service",
      "network",
      "credential",
      "tls",
      "certificate",
      "dns",
      "email-security",
      "subdomain",
      "web-headers",
      "cookie",
      "cors",
      "exposure",
      "http-method",
      "injection",
      "access-control",
      "auth",
      "integrity",
    ];
    for (const category of backendCategories) {
      expect(categoryLabel(category)).not.toBe(category);
    }
  });

  it("falls back to the raw value for an unknown category", () => {
    expect(categoryLabel("something-new")).toBe("something-new");
  });
});
