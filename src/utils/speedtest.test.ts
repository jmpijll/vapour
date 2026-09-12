import {test} from "node:test";
import assert from "node:assert/strict";
import {updateSpeedValues, runSpeedtest} from "./speedtest.ts";
test("new phases preserve earlier measurements",()=>{
  const values = updateSpeedValues({latency:12}, {run_id:"test",event:"progress",phase:"download",value:80});
  assert.deepEqual(values,{latency:12,download:80});
});
test("warmup and malformed measurements cannot become results",()=>{
  const initial={latency:12};
  for (const value of [NaN,Infinity,-1]) assert.equal(updateSpeedValues(initial,{run_id:"test",event:"progress",phase:"latency",value}),initial);
  assert.equal(updateSpeedValues(initial,{run_id:"test",event:"progress",phase:"latency",value:100,warmup:true}),initial);
});
test("browser cannot silently perform a substitute speedtest",async()=>{
  await assert.rejects(runSpeedtest(new AbortController().signal,()=>{}),/Open Vapour/);
});
