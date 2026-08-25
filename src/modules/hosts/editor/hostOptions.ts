import type { SshHost } from "../types";
import type { ComboboxOption } from "./Combobox";

/**
 * Saved SSH hosts as picker options, for the two rows that choose one: the SSH
 * jump host and the RDP tunnel. Both offered the same list rendered the same way,
 * differing only in what "none" is called.
 *
 * `user@` is shown only for an inline binding, because a vault-bound row keeps its
 * username on the identity and this list does not read the vault.
 */
export function savedHostOptions(hosts: SshHost[], noneLabel: string): ComboboxOption[] {
  return [
    { value: "", label: noneLabel, search: `none ${noneLabel}` },
    ...hosts.map((h) => {
      const user = h.credential.kind === "inline" ? `${h.credential.user}@` : "";
      return {
        value: h.id,
        label: `${h.name} (${user}${h.host}:${h.port})`,
        hint: `${user}${h.host}:${h.port}`,
        // Searchable on name + user@host:port; the id keeps the value unique so
        // cmdk never collapses two like-named hosts.
        search: `${h.name} ${user}${h.host}:${h.port} ${h.id}`,
      };
    }),
  ];
}
