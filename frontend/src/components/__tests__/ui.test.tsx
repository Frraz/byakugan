import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

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
