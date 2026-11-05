(() => {
  const panel = document.querySelector("#verify");
  const picker = panel.querySelector("input[type=file]");
  const result = panel.querySelector("[role=status]");
  const tag = panel.dataset.releaseTag;
  const repository = "Burntgogi/nikke-launcher-checker";
  const filename = "Nikke-Launcher-Checker.zip";
  let pending;

  function show(state) {
    result.dataset.state = state;
    result.textContent = panel.dataset[state];
  }

  picker.addEventListener("change", async () => {
    pending?.abort();
    pending = undefined;
    const file = picker.files[0];
    if (!file) {
      show("idle");
      return;
    }

    const controller = new AbortController();
    pending = controller;
    const timeout = setTimeout(() => controller.abort(), 12000);
    show("checking");
    try {
      const endpoint = "https://api.github.com/repos/" + repository + "/releases/tags/" + encodeURIComponent(tag);
      const response = await fetch(endpoint, {
        credentials: "omit",
        cache: "no-cache",
        signal: controller.signal
      });
      if (!response.ok) throw new Error("Release lookup failed");
      const release = await response.json();
      const asset = release.assets?.find(entry => entry.name === filename);
      if (release.tag_name !== tag || release.immutable !== true || release.draft !== false ||
          asset?.state !== "uploaded" || !/^sha256:[a-f0-9]{64}$/.test(asset?.digest) ||
          !Number.isSafeInteger(asset.size) || asset.size <= 0) {
        throw new Error("No trusted asset for this release");
      }

      let matches = false;
      if (file.size === asset.size) {
        const hash = await crypto.subtle.digest("SHA-256", await file.arrayBuffer());
        const hex = Array.from(new Uint8Array(hash), byte => byte.toString(16).padStart(2, "0")).join("");
        matches = "sha256:" + hex === asset.digest;
      }
      if (pending === controller) show(controller.signal.aborted ? "unavailable" : matches ? "match" : "mismatch");
    } catch {
      if (pending === controller) show("unavailable");
    } finally {
      clearTimeout(timeout);
    }
  });
})();
