/** Check the status bar's Tauri-free metric derivation. Run with
 * `pnpm verify resource-metrics-verify`. */
import {
  deriveResourceMetrics,
  type SshResourceSample,
} from "../src/modules/statusbar/resourceMetrics";

let failed = 0;
function check(label: string, got: unknown, want: unknown): void {
  if (JSON.stringify(got) === JSON.stringify(want)) {
    console.log(`  ok: ${label}`);
  } else {
    console.error(`  FAIL: ${label} = ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);
    failed++;
  }
}

const sample = (over: Partial<SshResourceSample> = {}): SshResourceSample => ({
  hostname: "node-a",
  version: "Linux 6.8",
  uptimeSeconds: 100,
  cpuTotal: 1000,
  cpuIdle: 800,
  memoryTotal: 4096,
  memoryAvailable: 2048,
  memoryCached: 512,
  memoryBuffers: 128,
  diskReadBytes: 20_000,
  diskWriteBytes: 30_000,
  filesystems: null,
  networkInterfaces: [
    {
      name: "eth0",
      receivedBytes: 10_000,
      receivedErrors: 0,
      receivedDropped: 0,
      sentBytes: 20_000,
      sentErrors: 0,
      sentDropped: 0,
    },
  ],
  ...over,
});

{
  const previous = sample({ uptimeSeconds: 100, cpuTotal: 500, cpuIdle: 350 });
  const current = sample({
    uptimeSeconds: 105,
    cpuTotal: 1000,
    cpuIdle: 450,
    diskReadBytes: 25_120,
    diskWriteBytes: 35_120,
    networkInterfaces: [
      {
        name: "eth0",
        receivedBytes: 15_120,
        receivedErrors: 1,
        receivedDropped: 2,
        sentBytes: 25_120,
        sentErrors: 3,
        sentDropped: 4,
      },
    ],
  });
  const got = deriveResourceMetrics(current, previous);
  check("CPU percentage", got.cpu, 80);
  check("network uses remote uptime delta", [got.rxRate, got.txRate], [1024, 1024]);
  check("disk I/O uses remote uptime delta", [got.diskReadRate, got.diskWriteRate], [1024, 1024]);
}

{
  const rootFs = [
    {
      source: "/dev/vda1",
      mount: "/",
      totalKib: 100,
      usedKib: 25,
      availableKib: 75,
      usePercent: 25,
    },
  ];
  const frames = [
    sample({ hostname: "node-a", version: "Linux 6.8", uptimeSeconds: 100, filesystems: rootFs }),
    sample({ hostname: null, version: null, uptimeSeconds: 101, filesystems: null }),
    sample({ hostname: null, version: null, uptimeSeconds: 102, filesystems: null }),
    sample({ hostname: null, version: null, uptimeSeconds: 103, filesystems: null }),
  ];
  let previous: SshResourceSample | null = null;
  let latest: SshResourceSample | null = null;
  for (const frame of frames) {
    const derived = deriveResourceMetrics(frame, previous);
    previous = derived.sample;
    latest = derived.sample;
  }
  check("hostname survives four frames when sent once", latest?.hostname, "node-a");
  check("version survives four frames when sent once", latest?.version, "Linux 6.8");
  check(
    "root filesystem survives four frames between 30s checks",
    latest?.filesystems?.[0]?.mount,
    "/",
  );
}

{
  const previous = sample({
    filesystems: [
      {
        source: "/dev/vda1",
        mount: "/",
        totalKib: 10,
        usedKib: 1,
        availableKib: 9,
        usePercent: 10,
      },
    ],
  });
  const got = deriveResourceMetrics(
    sample({
      uptimeSeconds: 101,
      cpuTotal: null,
      cpuIdle: null,
      memoryAvailable: null,
      networkInterfaces: [],
      filesystems: null,
    }),
    previous,
  );
  check("missing CPU is unavailable", got.cpu, null);
  check("missing network counters are unavailable", [got.rxRate, got.txRate], [null, null]);
  check("filesystem value persists between slower checks", got.sample.filesystems?.[0]?.mount, "/");
}

if (failed > 0) {
  console.error(`resource metrics verify: ${failed} failed`);
  process.exit(1);
}
console.log("resource metrics verify: all passed");
