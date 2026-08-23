#!/usr/bin/env node
/**
 * Rasterise the whole icon set from the two SVG sources in src-tauri/icons/.
 *
 * Run after editing `tervia-mark.svg` or `tervia-mark-foreground.svg`:
 *
 *   node scripts/gen-icons.mjs
 *
 * Not part of any build or CI job - icons change about once a product, and
 * the tools below are not worth adding to every contributor's setup. It
 * exists so the rasters are reproducible instead of being one-off exports
 * nobody can regenerate.
 *
 * Requires `rsvg-convert` (librsvg2-bin) and `convert` (ImageMagick). Chosen
 * over `tauri icon` because that command only accepts a raster input, so it
 * would resample an already-resampled PNG for every size instead of
 * rendering each one from the vector.
 *
 * The .icns is assembled here rather than by ImageMagick, which cannot read
 * the format and silently writes a single-frame file when asked to produce
 * one from several inputs.
 */
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const ICONS = join(ROOT, "src-tauri", "icons");
const MARK = join(ICONS, "tervia-mark.svg");
const FOREGROUND = join(ICONS, "tervia-mark-foreground.svg");
const STAGE = join(tmpdir(), "tervia-icons");

function run(cmd, args) {
  execFileSync(cmd, args, { stdio: ["ignore", "ignore", "inherit"] });
}

/** Render `svg` at `size`x`size` into `out`, creating parent dirs. */
function render(svg, size, out) {
  mkdirSync(dirname(out), { recursive: true });
  run("rsvg-convert", ["-w", String(size), "-h", String(size), svg, "-o", out]);
}

/**
 * Assemble an .icns from already-rendered PNGs. Layout is a 4-byte "icns"
 * magic, a big-endian u32 of the TOTAL file length, then one chunk per
 * entry: 4-byte OSType, big-endian u32 of (8 + payload), payload. Payload is
 * the PNG bytes verbatim - every OSType below is one of the PNG-accepting
 * types, so no legacy RLE encoder is needed.
 */
function buildIcns(entries, out) {
  const chunks = entries.map(([type, file]) => {
    const png = readFileSync(file);
    const header = Buffer.alloc(8);
    header.write(type, 0, 4, "ascii");
    header.writeUInt32BE(png.length + 8, 4);
    return Buffer.concat([header, png]);
  });
  const body = Buffer.concat(chunks);
  const header = Buffer.alloc(8);
  header.write("icns", 0, 4, "ascii");
  header.writeUInt32BE(body.length + 8, 4);
  writeFileSync(out, Buffer.concat([header, body]));
}

rmSync(STAGE, { recursive: true, force: true });
mkdirSync(STAGE, { recursive: true });

// --- square PNGs Tauri's desktop bundlers read -----------------------------
const DESKTOP = [
  [32, "32x32.png"],
  [64, "64x64.png"],
  [128, "128x128.png"],
  [256, "128x128@2x.png"],
  [512, "icon.png"],
];
for (const [size, name] of DESKTOP) render(MARK, size, join(ICONS, name));

// --- Windows Store tiles ---------------------------------------------------
const TILES = [30, 44, 71, 89, 107, 142, 150, 284, 310];
for (const size of TILES) render(MARK, size, join(ICONS, `Square${size}x${size}Logo.png`));
render(MARK, 50, join(ICONS, "StoreLogo.png"));

// --- icon.ico --------------------------------------------------------------
// Same size list the previous icon carried. 256 last: some Windows shells
// pick the final frame when several match, and the largest is the safe one.
const ICO_SIZES = [16, 24, 32, 48, 64, 256];
const icoParts = ICO_SIZES.map((size) => {
  const p = join(STAGE, `ico-${size}.png`);
  render(MARK, size, p);
  return p;
});
run("convert", [...icoParts, join(ICONS, "icon.ico")]);

// --- icon.icns -------------------------------------------------------------
// Both the plain and the @2x OSType for each logical size, which is what
// Finder and the Dock expect from a modern bundle.
const ICNS = [
  ["icp4", 16],
  ["icp5", 32],
  ["ic11", 32],
  ["ic12", 64],
  ["ic07", 128],
  ["ic13", 256],
  ["ic08", 256],
  ["ic14", 512],
  ["ic09", 512],
  ["ic10", 1024],
];
buildIcns(
  ICNS.map(([type, size]) => {
    const p = join(STAGE, `icns-${type}.png`);
    render(MARK, size, p);
    return [type, p];
  }),
  join(ICONS, "icon.icns"),
);

// --- mobile ----------------------------------------------------------------
// Tervia ships desktop only, but `tauri icon` writes these and a future
// mobile target would expect them present rather than stale.
const ANDROID = [
  ["mdpi", 48, 108],
  ["hdpi", 49, 162],
  ["xhdpi", 96, 216],
  ["xxhdpi", 144, 324],
  ["xxxhdpi", 192, 432],
];
for (const [density, launcher, foreground] of ANDROID) {
  const dir = join(ICONS, "android", `mipmap-${density}`);
  render(MARK, launcher, join(dir, "ic_launcher.png"));
  render(MARK, launcher, join(dir, "ic_launcher_round.png"));
  render(FOREGROUND, foreground, join(dir, "ic_launcher_foreground.png"));
}

const IOS = [
  ["20x20@1x", 20],
  ["20x20@2x", 40],
  ["20x20@2x-1", 40],
  ["20x20@3x", 60],
  ["29x29@1x", 29],
  ["29x29@2x", 58],
  ["29x29@2x-1", 58],
  ["29x29@3x", 87],
  ["40x40@1x", 40],
  ["40x40@2x", 80],
  ["40x40@2x-1", 80],
  ["40x40@3x", 120],
  ["60x60@2x", 120],
  ["60x60@3x", 180],
  ["76x76@1x", 76],
  ["76x76@2x", 152],
  ["83.5x83.5@2x", 167],
  ["512@2x", 1024],
];
for (const [name, size] of IOS) render(MARK, size, join(ICONS, "ios", `AppIcon-${name}.png`));

// --- repo-level logo -------------------------------------------------------
render(MARK, 750, join(ROOT, "tervia.png"));

rmSync(STAGE, { recursive: true, force: true });
console.log("gen-icons: wrote the icon set from tervia-mark.svg");
