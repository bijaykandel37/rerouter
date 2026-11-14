/** Chart colors are read from CSS tokens so light/dark stay in one place. */

export function cssVar(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

export const SLOTS = ["--series-1", "--series-2", "--series-3", "--series-4", "--series-5", "--series-6", "--series-7"];

/** Fixed meaning for traffic direction everywhere in the UI. */
export const DIRECTION_SLOT: Record<string, number> = { download: 0, upload: 1, lan: 2, transit: 3 };
export const DIRECTION_LABEL: Record<string, string> = {
  download: "Download", upload: "Upload", lan: "LAN ↔ LAN", transit: "Transit",
};

/**
 * Color follows the entity, never its rank: the first time a key is seen it
 * gets the next free slot, and keeps it for the session. Past 7 entities the
 * remainder share the neutral "other" color (and are folded server-side).
 */
const assigned = new Map<string, number>();
export function slotFor(key: string, scope = "default"): number {
  const k = `${scope}:${key}`;
  let slot = assigned.get(k);
  if (slot === undefined) {
    const used = new Set([...assigned.entries()].filter(([kk]) => kk.startsWith(scope + ":")).map(([, v]) => v));
    slot = [0, 1, 2, 3, 4, 5, 6].find((s) => !used.has(s)) ?? -1;
    assigned.set(k, slot);
  }
  return slot;
}

export function colorFor(key: string, scope = "default"): string {
  if (key === "__other__") return cssVar("--series-other");
  if (scope === "direction" && key in DIRECTION_SLOT) return cssVar(SLOTS[DIRECTION_SLOT[key]]);
  const slot = slotFor(key, scope);
  return slot < 0 ? cssVar("--series-other") : cssVar(SLOTS[slot]);
}

export function seqRamp(): string[] {
  return ["--seq-0", "--seq-1", "--seq-2", "--seq-3", "--seq-4", "--seq-5"].map(cssVar);
}
