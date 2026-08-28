// The primitives every ranked search in the app shares.
//
// Extracted rather than copied because two search surfaces disagreeing about what
// counts as a word boundary is exactly the class of divergence that already cost
// this project once: the Hosts page and the header quick-connect both called one
// ranking function and still disagreed, because each assembled its own input. A
// shared function guarantees nothing about callers that build their arguments
// separately - so share the smallest thing both callers can share, and share it
// rather than describing it.
//
// Pure: no React, no Tauri, no store. Both `modules/hosts/search.ts` and
// `modules/vault/page/derive.ts` import it, and both verify scripts exercise it.

/**
 * Word-boundary delimiters. Matches the punctuation people actually put in host,
 * machine and account names ("prod-db-01", "prod_db", "db.internal", "prod db");
 * anything else falls through to a plain substring test one tier down.
 */
export const WORD_BOUNDARY = /[.\-_ ]/;

/** True when `query` starts one of `value`'s delimiter-separated words. */
export function hasWordBoundaryMatch(value: string, query: string): boolean {
  return value.split(WORD_BOUNDARY).some((word) => word.length > 0 && word.startsWith(query));
}
