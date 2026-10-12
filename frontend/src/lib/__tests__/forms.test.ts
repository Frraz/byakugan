import { describe, expect, it } from "vitest";
import { isTargetValue, targetFormSchema } from "../forms";

describe("target input format (RN001)", () => {
  it.each(["localhost", "api.example.test", "192.0.2.1", "2001:db8::1", "10.0.0.0/24", "2001:db8::/64"])("accepts %s", (value) => expect(isTargetValue(value)).toBe(true));
  it.each(["", "https://example.test", "example.test/path", "10.0.0.0/33", "2001:db8::/129", "bad host", "-host", "host..test"])("rejects %s", (value) => expect(isTargetValue(value)).toBe(false));
  it("rejects invalid dates before converting them to ISO", () => {
    expect(targetFormSchema.safeParse({ name: "Lab", value: "localhost", authorization_scope: "", authorization_expires_at: "invalid", is_active: true }).success).toBe(false);
  });
});
