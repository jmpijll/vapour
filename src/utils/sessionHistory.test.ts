import { test } from "node:test";
import assert from "node:assert/strict";
import { retainSessions } from "./sessionHistory.ts";
import type { ProcessTraffic } from "../types.ts";
const proc = (ids: string[]) =>
  ({
    pid: 1,
    path: "C:\\demo.exe",
    name: "demo.exe",
    sockets: ids.map((id) => ({ id, state: "ESTABLISHED" })),
  }) as ProcessTraffic;
test("keeps closed sessions in place for 30 seconds, without extending expiry", () => {
  const first = retainSessions([], [proc(["a", "b"])], 1000);
  const second = retainSessions(first, [proc(["b", "c"])], 2000);
  assert.deepEqual(
    second[0].sockets.map((s) => s.id),
    ["a", "b", "c"],
  );
  assert.equal(second[0].sockets[0].closed_at, 2000);
  const later = retainSessions(second, [proc(["b", "c"])], 31000);
  assert.equal(later[0].sockets[0].closed_at, 2000);
  assert.deepEqual(
    retainSessions(later, [proc(["b", "c"])], 32000)[0].sockets.map(
      (s) => s.id,
    ),
    ["b", "c"],
  );
});
test("keeps an exited app briefly, but never carries its old rate forward", () => {
  const first = retainSessions(
    [],
    [{ ...proc(["a"]), download_speed_bps: 900 }],
    1000,
  );
  const closed = retainSessions(first, [], 2000);
  assert.equal(closed.length, 1);
  assert.equal(closed[0].download_speed_bps, 0);
  assert.equal(retainSessions(closed, [], 32000).length, 0);
});
