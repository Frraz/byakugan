import { describe, expect, it } from "vitest";

import { formatBytes, formatDuration } from "../format";

describe("formatBytes", () => {
  it("formats bytes into human-readable units", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(1024)).toBe("1 KB");
    expect(formatBytes(1536)).toBe("1.5 KB");
    expect(formatBytes(1048576)).toBe("1 MB");
  });

  it("returns a dash for nullish values", () => {
    expect(formatBytes(null)).toBe("—");
    expect(formatBytes(undefined)).toBe("—");
  });
});

describe("formatDuration", () => {
  it("formats the elapsed time between two instants", () => {
    const start = "2026-01-01T00:00:00Z";
    expect(formatDuration(start, "2026-01-01T00:00:45Z")).toBe("45 s");
    expect(formatDuration(start, "2026-01-01T00:02:13Z")).toBe("2 min 13 s");
    expect(formatDuration(start, "2026-01-01T01:05:00Z")).toBe("1 h 5 min");
  });

  it("returns a dash when either instant is missing", () => {
    expect(formatDuration(null, "2026-01-01T00:00:00Z")).toBe("—");
  });
});
