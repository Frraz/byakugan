import { cleanup, renderHook } from "@testing-library/react";
import { afterEach, expect, it } from "vitest";
import { useAuthStore } from "@/store/auth";
import type { Role } from "@/lib/types";
import { usePermissions } from "../usePermissions";

afterEach(() => { cleanup(); useAuthStore.getState().clear(); });
it.each<[Role, boolean, boolean]>([["admin", true, true], ["analyst", true, false], ["viewer", false, false]])("mirrors backend permissions for %s", (role, canWrite, isAdmin) => {
  useAuthStore.setState({ user: { id: "u", email: "lab@example.test", role, is_active: true } });
  expect(renderHook(() => usePermissions()).result.current).toMatchObject({ role, canWrite, isAdmin });
});
