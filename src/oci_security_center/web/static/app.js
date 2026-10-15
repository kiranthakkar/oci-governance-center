// OCI Security Center — tiny progressive enhancement. No inline scripts (CSP: script-src 'self').
"use strict";

document.addEventListener("DOMContentLoaded", () => {
  // Copy-to-clipboard buttons: <button data-copy="element-id">
  document.querySelectorAll("[data-copy]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const el = document.getElementById(btn.dataset.copy);
      if (!el) return;
      const original = btn.textContent;
      try {
        await navigator.clipboard.writeText(el.textContent.trim() + "\n");
        btn.textContent = "Copied";
      } catch (e) {
        btn.textContent = "Copy failed — use Download";
      }
      setTimeout(() => { btn.textContent = original; }, 1600);
    });
  });

  // Connection forms: show only the fieldsets for the selected method.
  document.querySelectorAll("[data-conn]").forEach((form) => {
    const select = form.querySelector("[data-method-select]");
    const sync = () => {
      form.querySelectorAll("fieldset[data-for]").forEach((fs) => {
        const show = fs.dataset.for.split(" ").includes(select.value);
        fs.hidden = !show;
        fs.disabled = !show;
      });
    };
    select.addEventListener("change", sync);
    sync();
  });
});
