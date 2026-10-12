import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ReportFormDialog } from "../ReportFormDialog";

const mocks = vi.hoisted(() => ({
  scans: vi.fn(),
  create: vi.fn(),
  reset: vi.fn(),
  mutate: vi.fn(),
  refetch: vi.fn(),
}));

vi.mock("@/hooks/useData", () => ({
  useScans: mocks.scans,
  useCreateReport: mocks.create,
}));

beforeEach(() => {
  vi.clearAllMocks();
  mocks.scans.mockReturnValue({
    data: { results: [], count: 0 }, isLoading: false, isError: false, refetch: mocks.refetch,
  });
  mocks.create.mockReturnValue({ reset: mocks.reset, mutate: mocks.mutate, isPending: false });
});

describe("report generation states", () => {
  it("announces loading without claiming there are no completed scans", () => {
    mocks.scans.mockReturnValue({ isLoading: true });
    render(<ReportFormDialog open onOpenChange={vi.fn()} />);
    expect(screen.getByRole("status")).toHaveTextContent("Carregando scans concluídos");
    expect(screen.queryByText("Nenhum scan concluído")).not.toBeInTheDocument();
  });

  it("offers retry when the scan request fails", () => {
    mocks.scans.mockReturnValue({ isError: true, error: new Error("Offline"), refetch: mocks.refetch });
    render(<ReportFormDialog open onOpenChange={vi.fn()} />);
    expect(screen.getByRole("alert")).toBeInTheDocument();
    expect(screen.queryByText("Nenhum scan concluído")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Tentar novamente" }));
    expect(mocks.refetch).toHaveBeenCalledOnce();
  });

  it("shows the empty state only after a successful empty response", () => {
    render(<ReportFormDialog open onOpenChange={vi.fn()} />);
    expect(screen.getByText("Nenhum scan concluído")).toBeInTheDocument();
  });

  it("can reach completed scans beyond the first page and labels every field", () => {
    mocks.scans.mockReturnValue({
      data: { count: 21, results: [{ id: "scan-1", target: "example.test", created_at: "2026-10-11T10:00:00Z" }] },
    });
    render(<ReportFormDialog open onOpenChange={vi.fn()} />);
    expect(screen.getByRole("combobox", { name: "Scan concluído" })).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Tipo" })).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Formato" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Gerar relatório" })).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: /Próxima/ }));
    expect(mocks.scans).toHaveBeenLastCalledWith({ status: "completed", page: 2 }, true);
  });

  it("does not request scans while the dialog is closed", () => {
    render(<ReportFormDialog open={false} onOpenChange={vi.fn()} />);
    expect(mocks.scans).toHaveBeenCalledWith({ status: "completed", page: 1 }, false);
  });
});
