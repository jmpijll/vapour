const { test } = require("node:test");
const assert = require("node:assert/strict");
const { nightlyTag, planNightly, requiredAssets } = require("./nightly-plan.cjs");
const sha = "a".repeat(40);
const input = { sha, ref: "refs/heads/main", event: "push", release: null };
const release = { target_commitish: sha, tag_name: nightlyTag(sha), prerelease: true, draft: false,
  assets: requiredAssets.map(name => ({ name, size: 100 })) };
test("new main changes build and publish", () => {
  assert.deepEqual(planNightly(input), { tag: nightlyTag(sha), build: true, publish: true });
});
test("PRs and branch dispatches build but cannot publish", () => {
  assert.equal(planNightly({ ...input, event: "pull_request" }).publish, false);
  assert.equal(planNightly({ ...input, ref: "refs/heads/feature" }).publish, false);
});
test("unchanged successful commits skip build and publication", () => {
  assert.deepEqual(planNightly({ ...input, event: "schedule", release }), { tag: nightlyTag(sha), build: false, publish: false });
});
test("unpublished drafts are retried", () => {
  assert.equal(planNightly({ ...input, release: { ...release, draft: true } }).publish, true);
});
test("a failed previous run without a release is retried nightly", () => {
  assert.equal(planNightly({ ...input, event: "schedule" }).build, true);
});
test("different main commits produce distinct releases", () => {
  assert.notEqual(nightlyTag(sha), nightlyTag("b".repeat(40)));
});
test("wrong commit/channel and incomplete published assets fail closed", () => {
  for (const changed of [{ target_commitish: "main" }, { prerelease: false }, { tag_name: "nightly" },
    { assets: [] }, { assets: requiredAssets.map(name => ({ name, size: 0 })) }])
    assert.throws(() => planNightly({ ...input, release: { ...release, ...changed } }));
});
test("malformed commit identifiers are rejected", () => assert.throws(() => nightlyTag("main")));
