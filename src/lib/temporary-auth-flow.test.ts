import assert from "node:assert/strict";
import test from "node:test";
import { clearTemporaryAuthFlow, grantTemporaryAuthFlow, hasTemporaryAuthFlow } from "./temporary-auth-flow";

test("temporary flows are bound to the user and expire", () => {
  const values = new Map<string, string>();
  const storage = {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => { values.set(key, value); },
    removeItem: (key: string) => { values.delete(key); },
  };
  const previousStorage = Object.getOwnPropertyDescriptor(globalThis, "sessionStorage");
  const previousNow = Date.now;
  Object.defineProperty(globalThis, "sessionStorage", { configurable: true, value: storage });
  Date.now = () => 1_000;
  try {
    assert.equal(grantTemporaryAuthFlow("invite", "user-a"), true);
    assert.equal(hasTemporaryAuthFlow("invite", "user-a"), true);
    assert.equal(hasTemporaryAuthFlow("recovery", "user-a"), false);
    assert.equal(grantTemporaryAuthFlow("recovery", "user-a"), true);
    assert.equal(hasTemporaryAuthFlow("recovery", "user-b"), false);
    grantTemporaryAuthFlow("recovery", "user-a");
    Date.now = () => 21 * 60 * 1_000;
    assert.equal(hasTemporaryAuthFlow("recovery", "user-a"), false);
    clearTemporaryAuthFlow();
  } finally {
    Date.now = previousNow;
    if (previousStorage) Object.defineProperty(globalThis, "sessionStorage", previousStorage);
    else Reflect.deleteProperty(globalThis, "sessionStorage");
  }
});
