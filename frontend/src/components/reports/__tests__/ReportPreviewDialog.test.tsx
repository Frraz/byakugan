import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { Report } from "@/lib/types";
import { ReportPreviewDialog } from "../ReportPreviewDialog";

const mocks = vi.hoisted(() => ({ fetchBlob: vi.fn() }));
vi.mock("@/lib/api", async (importOriginal) => ({
  ...await importOriginal<typeof import("@/lib/api")>(),
  fetchBlob: mocks.fetchBlob,
}));

const report: Report = {
  id: "report-1", scan: "scan-1", scan_target: "example.test", scan_type: "full",
  scan_finished_at: null, report_type: "technical", format: "pdf", file_path: "",
  file_size: 100, created_by: "analyst", created_at: "2026-10-11T10:00:00Z",
};

beforeEach(() => {
  mocks.fetchBlob.mockReset();
  URL.createObjectURL = vi.fn(() => "blob:report-preview");
  URL.revokeObjectURL = vi.fn();
});

describe("report preview lifecycle", () => {
  it("retries a failed authenticated download and releases its PDF URL on close", async () => {
    mocks.fetchBlob.mockRejectedValueOnce(new Error("Offline")).mockResolvedValueOnce(new Blob());
    const { unmount } = render(
      <ReportPreviewDialog report={report} onOpenChange={vi.fn()} onDownload={vi.fn()} />,
    );
    await screen.findByRole("alert");
    fireEvent.click(screen.getByRole("button", { name: "Tentar novamente" }));
    expect(await screen.findByTitle("Pré-visualização do relatório")).toHaveAttribute("src", "blob:report-preview");
    expect(mocks.fetchBlob).toHaveBeenCalledTimes(2);
    expect(mocks.fetchBlob).toHaveBeenLastCalledWith("/reports/report-1/download/");
    unmount();
    expect(URL.revokeObjectURL).toHaveBeenCalledWith("blob:report-preview");
  });

  it("ignores a late JSON body after switching to another report", async () => {
    let resolveText!: (text: string) => void;
    mocks.fetchBlob.mockResolvedValueOnce({ text: () => new Promise<string>((resolve) => { resolveText = resolve; }) });
    const props = { onOpenChange: vi.fn(), onDownload: vi.fn() };
    const { rerender } = render(<ReportPreviewDialog report={{ ...report, format: "json" }} {...props} />);
    await waitFor(() => expect(resolveText).toBeDefined());
    mocks.fetchBlob.mockResolvedValueOnce({ text: async () => '{"current":true}' });
    rerender(<ReportPreviewDialog report={{ ...report, id: "report-2", format: "json" }} {...props} />);
    await screen.findByText(/"current": true/);
    resolveText('{"obsolete":true}');
    await waitFor(() => expect(screen.queryByText(/"obsolete"/)).not.toBeInTheDocument());
    expect(screen.getByText(/"current": true/)).toBeInTheDocument();
  });
});
