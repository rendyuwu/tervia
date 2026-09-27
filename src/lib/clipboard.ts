import { invoke } from "@tauri-apps/api/core";

/**
 * Clipboard text, or "" when there is nothing text-shaped to paste.
 *
 * Reads go through the host process (`clipboard_read_text`), NOT
 * `navigator.clipboard.readText()`. The webview API is write-only for us: wry
 * calls WebKitGTK's `set_javascript_can_access_clipboard` - which also flips
 * WebCore's `DOMPasteAllowed`, the flag gating clipboard READS - only when the
 * webview is built with `clipboard: true`, and Tauri defaults that to false with
 * no tauri.conf.json knob to raise it for a config-declared window. So on Linux
 * every `readText()` rejected with NotAllowedError while `writeText()` kept
 * working off the keystroke's user gesture: copy fine, paste dead.
 *
 * Callers get "" rather than a rejection - an empty or image-only clipboard is
 * not an error, it just means "nothing to paste" - so paste sites stay a single
 * `if (text)` with no per-site catch.
 */
export async function readClipboardText(): Promise<string> {
  try {
    return await invoke<string>("clipboard_read_text");
  } catch (e) {
    console.warn("clipboard read failed:", e);
    return "";
  }
}

/**
 * Local paths an OS file manager copied, read through the host process
 * (`clipboard_read_file_list`). `[]` means nothing file-shaped to paste, the
 * same no-throw contract as `readClipboardText`.
 */
export async function readClipboardFiles(): Promise<string[]> {
  try {
    return await invoke<string[]>("clipboard_read_file_list");
  } catch (e) {
    console.warn("clipboard file read failed:", e);
    return [];
  }
}

/**
 * Write through the host process (`clipboard_write_text`), for writes that
 * come with no user gesture: an OSC 52 copy arrives on the PTY stream. Copies
 * the user makes (select-to-copy, right-click, Ctrl+Shift+C) stay on
 * `navigator.clipboard.writeText`. Never rejects; a failure is logged, the
 * same contract as the reads above.
 */
export async function writeClipboardText(text: string): Promise<void> {
  try {
    await invoke("clipboard_write_text", { text });
  } catch (e) {
    console.warn("clipboard write failed:", e);
  }
}
