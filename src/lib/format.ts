/** Human-readable byte size: `n B` / `x.x KB` / `x.x MB` (1024-based). */
export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

// Module-level, not one per call - see RELEASE_DATE_FORMAT in UpdaterDialog.
const RELATIVE_TIME_FORMAT = new Intl.RelativeTimeFormat("en", { numeric: "always" });

// Largest unit first: a host connected 400 days ago should read "1 year ago",
// not "57 weeks ago".
const RELATIVE_TIME_UNITS: ReadonlyArray<readonly [Intl.RelativeTimeFormatUnit, number]> = [
  ["year", 365 * 24 * 60 * 60 * 1000],
  ["month", 30 * 24 * 60 * 60 * 1000],
  ["week", 7 * 24 * 60 * 60 * 1000],
  ["day", 24 * 60 * 60 * 1000],
  ["hour", 60 * 60 * 1000],
  ["minute", 60 * 1000],
];

/**
 * "Connected 3 days ago", or undefined for a record never connected from this
 * device (renders nothing). One wording for every `lastConnectedAt` a card shows
 * - hosts, vault identities and vault keys - so the recency each list is sorted
 * by reads the same everywhere.
 *
 * `now` is a parameter, not `Date.now()` read in here, so the label stays
 * pure and deterministic.
 */
export function lastConnectedLabel(at: number | undefined, now: number): string | undefined {
  if (at === undefined) return undefined;
  const elapsed = now - at;
  for (const [unit, unitMs] of RELATIVE_TIME_UNITS) {
    const count = Math.floor(elapsed / unitMs);
    if (count >= 1) return `Connected ${RELATIVE_TIME_FORMAT.format(-count, unit)}`;
  }
  // Under a minute, a future stamp (negative elapsed), or NaN all fail every
  // arm above and land here.
  return "Connected just now";
}
