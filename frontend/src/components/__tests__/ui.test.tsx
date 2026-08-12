import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { SeverityBadge, StatusBadge } from "../ui";

describe("SeverityBadge", () => {
  it("renders the severity label and aria-label", () => {
    render(<SeverityBadge severity="critical" />);
    const badge = screen.getByLabelText("Severidade critical");
    expect(badge).toBeInTheDocument();
    expect(badge).toHaveTextContent(/critical/i);
  });
});

describe("StatusBadge", () => {
  it("maps scan status to a localized label", () => {
    render(<StatusBadge status="running" />);
    expect(screen.getByText("Executando")).toBeInTheDocument();
  });
});
