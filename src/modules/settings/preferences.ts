import { create } from "zustand";
import { normalizeCustomTheme } from "./customTheme";
import {
  DEFAULT_PREFERENCES,
  loadPreferences,
  onPreferencesChange,
  type Preferences,
} from "./store";

type State = Preferences & {
  hydrated: boolean;
  /** Subscribe and hydrate. Idempotent; safe to call from multiple windows. */
  init: () => Promise<void>;
};

let initialized = false;

export const usePreferencesStore = create<State>((set) => ({
  ...DEFAULT_PREFERENCES,
  hydrated: false,
  init: async () => {
    if (initialized) return;
    initialized = true;
    const prefs = await loadPreferences();
    set({ ...prefs, hydrated: true });
    void onPreferencesChange((key, value) => {
      if (key === "customTheme") {
        const normalized = normalizeCustomTheme(value, DEFAULT_PREFERENCES.customTheme);
        set({ customTheme: normalized });
        return;
      }
      set({ [key]: value } as Partial<State>);
    });
  },
}));
