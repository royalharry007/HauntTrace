import { describe, expect, it } from "vitest";
import { formatBytes, formatDuration, hhmmToMinutes, minutesToHHMM, splitEvidenceRefs, timeAgo } from "./format";

describe("format", () => {
  it("formats bytes", () => {
    expect(formatBytes(null)).toBe("—");
    expect(formatBytes(512 * 1024)).toBe("512 KB");
    expect(formatBytes(5.5 * 1024 * 1024)).toBe("5.5 MB");
    expect(formatBytes(300 * 1024 * 1024)).toBe("300 MB");
    expect(formatBytes(2 * 1024 ** 3)).toBe("2.00 GB");
  });

  it("formats durations", () => {
    expect(formatDuration(42_000)).toBe("42s");
    expect(formatDuration(125_000)).toBe("2m 5s");
    expect(formatDuration(3 * 3_600_000 + 60_000)).toBe("3h 1m");
    expect(formatDuration(-1)).toBe("—");
  });

  it("round-trips quiet hours", () => {
    expect(minutesToHHMM(22 * 60 + 5)).toBe("22:05");
    expect(hhmmToMinutes("07:30")).toBe(450);
    expect(hhmmToMinutes("bad")).toBe(0);
  });

  it("describes relative time", () => {
    expect(timeAgo(1000, 2000)).toBe("just now");
    expect(timeAgo(0, 10 * 60_000)).toBe("10 min ago");
  });

  it("finds evidence references", () => {
    expect(splitEvidenceRefs("CPU high (E1, E3).")).toEqual([
      { text: "CPU high (" },
      { text: "E1", ref: "E1" },
      { text: ", " },
      { text: "E3", ref: "E3" },
      { text: ")." },
    ]);
    expect(splitEvidenceRefs("no refs")).toEqual([{ text: "no refs" }]);
  });
});
