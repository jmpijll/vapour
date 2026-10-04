const requiredAssets = ["Vapour-windows-x64.zip", "SHA256SUMS.txt", "release.json"];
function nightlyTag(sha) {
  if (!/^[a-f0-9]{40}$/.test(sha)) throw new Error("Expected a full Git commit SHA");
  return `nightly-${sha}`;
}
function planNightly({ sha, ref, event, release }) {
  const tag = nightlyTag(sha);
  const publish = ref === "refs/heads/main" && event !== "pull_request";
  if (!publish) return { tag, build: true, publish: false };
  if (!release) return { tag, build: true, publish: true };
  if (release.target_commitish !== sha || release.tag_name !== tag || !release.prerelease)
    throw new Error("Existing nightly does not match the expected commit/channel");
  if (release.draft) return { tag, build: true, publish: true };
  if (!requiredAssets.every(name => release.assets.some(asset => asset.name === name && asset.size > 0)))
    throw new Error("Published nightly is incomplete; retain it for maintainer inspection");
  return { tag, build: false, publish: false };
}
module.exports = { nightlyTag, planNightly, requiredAssets };
