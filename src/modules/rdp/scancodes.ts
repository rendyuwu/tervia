/**
 * `KeyboardEvent.code` -> PC/AT set-1 scancode, with the `0xE0` prefix folded
 * into the high byte (so the extended left arrow is `0xE04B`).
 *
 * This has to be a static table, not a derivation. `KeyboardEvent.key` is what
 * the user's layout PRODUCED and carries no scancode; `code` is the physical
 * key, which is what a scancode names. RDP's `SCANCODE` input event is
 * position-based and the server applies its own layout, so shipping `code`'s
 * scancode is what makes a French keyboard type French on a French desktop
 * without Tervia knowing anything about either layout.
 *
 * The extended flag is not cosmetic: without it the arrow keys, right-hand
 * modifiers, and the navigation cluster arrive as their numpad twins, so
 * Ctrl+Right becomes Ctrl+Numpad6 and Delete becomes Numpad-period.
 *
 * Keys deliberately absent:
 *
 * * `Pause` - its make code is the three-byte `0xE1 0x1D 0x45` sequence, which
 *   cannot be expressed in the u16 the backend takes. Dropped rather than
 *   approximated with something that would type a different key.
 * * `Fn`, `FnLock`, `Hyper`, `Super`, `Turbo`, `Again`, `Props`, `Undo`, `Cut`,
 *   `Copy`, `Paste`, `Find`, `Open`, `Select` - no set-1 make code exists on a
 *   PC keyboard, so there is nothing to send.
 *
 * A key with no entry falls through to the Unicode path in `RdpPane`, which is
 * also how dead keys and IME output travel.
 */
const SCANCODES: Readonly<Record<string, number>> = {
  // Row 1
  Escape: 0x0001,
  Digit1: 0x0002,
  Digit2: 0x0003,
  Digit3: 0x0004,
  Digit4: 0x0005,
  Digit5: 0x0006,
  Digit6: 0x0007,
  Digit7: 0x0008,
  Digit8: 0x0009,
  Digit9: 0x000a,
  Digit0: 0x000b,
  Minus: 0x000c,
  Equal: 0x000d,
  Backspace: 0x000e,

  // Row 2
  Tab: 0x000f,
  KeyQ: 0x0010,
  KeyW: 0x0011,
  KeyE: 0x0012,
  KeyR: 0x0013,
  KeyT: 0x0014,
  KeyY: 0x0015,
  KeyU: 0x0016,
  KeyI: 0x0017,
  KeyO: 0x0018,
  KeyP: 0x0019,
  BracketLeft: 0x001a,
  BracketRight: 0x001b,
  Enter: 0x001c,

  // Row 3
  ControlLeft: 0x001d,
  KeyA: 0x001e,
  KeyS: 0x001f,
  KeyD: 0x0020,
  KeyF: 0x0021,
  KeyG: 0x0022,
  KeyH: 0x0023,
  KeyJ: 0x0024,
  KeyK: 0x0025,
  KeyL: 0x0026,
  Semicolon: 0x0027,
  Quote: 0x0028,
  Backquote: 0x0029,

  // Row 4
  ShiftLeft: 0x002a,
  Backslash: 0x002b,
  KeyZ: 0x002c,
  KeyX: 0x002d,
  KeyC: 0x002e,
  KeyV: 0x002f,
  KeyB: 0x0030,
  KeyN: 0x0031,
  KeyM: 0x0032,
  Comma: 0x0033,
  Period: 0x0034,
  Slash: 0x0035,
  ShiftRight: 0x0036,

  // Row 5
  AltLeft: 0x0038,
  Space: 0x0039,
  CapsLock: 0x003a,

  // Function row
  F1: 0x003b,
  F2: 0x003c,
  F3: 0x003d,
  F4: 0x003e,
  F5: 0x003f,
  F6: 0x0040,
  F7: 0x0041,
  F8: 0x0042,
  F9: 0x0043,
  F10: 0x0044,
  F11: 0x0057,
  F12: 0x0058,
  // The 122-key extras. Rare, but they cost one line each and a terminal
  // emulator running on the remote may well be bound to them.
  F13: 0x0064,
  F14: 0x0065,
  F15: 0x0066,
  F16: 0x0067,
  F17: 0x0068,
  F18: 0x0069,
  F19: 0x006a,
  F20: 0x006b,
  F21: 0x006c,
  F22: 0x006d,
  F23: 0x006e,
  F24: 0x0076,

  // Numpad. NumpadEnter and NumpadDivide are the extended pair; the rest are
  // the original XT block, which is why they collide with the navigation
  // cluster below and why that cluster must carry the 0xE0 flag.
  NumLock: 0x0045,
  ScrollLock: 0x0046,
  Numpad7: 0x0047,
  Numpad8: 0x0048,
  Numpad9: 0x0049,
  NumpadSubtract: 0x004a,
  Numpad4: 0x004b,
  Numpad5: 0x004c,
  Numpad6: 0x004d,
  NumpadAdd: 0x004e,
  Numpad1: 0x004f,
  Numpad2: 0x0050,
  Numpad3: 0x0051,
  Numpad0: 0x0052,
  NumpadDecimal: 0x0053,
  NumpadMultiply: 0x0037,
  NumpadDivide: 0xe035,
  NumpadEnter: 0xe01c,

  /** The extra key ISO layouts have beside the left Shift. */
  IntlBackslash: 0x0056,
  /** JIS keys. Present so a Japanese keyboard can reach a Japanese desktop. */
  IntlRo: 0x0073,
  IntlYen: 0x007d,
  KanaMode: 0x0070,
  Convert: 0x0079,
  NonConvert: 0x007b,
  Lang1: 0x0072,
  Lang2: 0x0071,

  // Extended: right-hand modifiers, the Windows keys, and the menu key.
  ControlRight: 0xe01d,
  AltRight: 0xe038,
  MetaLeft: 0xe05b,
  MetaRight: 0xe05c,
  ContextMenu: 0xe05d,

  // Extended: navigation cluster. Same low bytes as the numpad above, which is
  // exactly what the 0xE0 flag distinguishes.
  Insert: 0xe052,
  Delete: 0xe053,
  Home: 0xe047,
  End: 0xe04f,
  PageUp: 0xe049,
  PageDown: 0xe051,
  ArrowUp: 0xe048,
  ArrowDown: 0xe050,
  ArrowLeft: 0xe04b,
  ArrowRight: 0xe04d,
  PrintScreen: 0xe037,

  // Extended: the multimedia / ACPI block. Cheap to include and the remote may
  // have something bound to them.
  AudioVolumeMute: 0xe020,
  AudioVolumeDown: 0xe02e,
  AudioVolumeUp: 0xe030,
  MediaTrackNext: 0xe019,
  MediaTrackPrevious: 0xe010,
  MediaStop: 0xe024,
  MediaPlayPause: 0xe022,
  LaunchMail: 0xe06c,
  LaunchApp1: 0xe06b,
  LaunchApp2: 0xe021,
  BrowserSearch: 0xe065,
  BrowserFavorites: 0xe066,
  BrowserRefresh: 0xe067,
  BrowserStop: 0xe068,
  BrowserForward: 0xe069,
  BrowserBack: 0xe06a,
  BrowserHome: 0xe032,
  Power: 0xe05e,
  Sleep: 0xe05f,
  WakeUp: 0xe063,
};

/** The scancode for a `KeyboardEvent.code`, or `undefined` when the key has no
 *  set-1 make code (see the module docs for what is deliberately missing). */
export function scancodeFor(code: string): number | undefined {
  return SCANCODES[code];
}

/**
 * The chord the webview cannot let through: on Windows Ctrl+Alt+Del is a
 * Secure Attention Sequence handled by the OS before any application sees it,
 * and on Linux and macOS it is not a keystroke the browser reports either. So
 * it is sent as an explicit action instead, from the pane header.
 *
 * Order matters, and the releases must mirror the presses: the server tracks
 * modifier state, so leaving Ctrl or Alt held would strand them down on the
 * remote for every later keystroke.
 */
export const CTRL_ALT_DEL_SCANCODES = {
  down: [SCANCODES.ControlLeft, SCANCODES.AltLeft, SCANCODES.Delete],
  up: [SCANCODES.Delete, SCANCODES.AltLeft, SCANCODES.ControlLeft],
} as const;
