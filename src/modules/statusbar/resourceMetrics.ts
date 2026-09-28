/** Wire shape for resource samples. Kept independent from Tauri so rate math
 * can be consumed by scripts without loading a webview API. */
export type SshResourceSample = {
  hostname: string | null;
  version: string | null;
  uptimeSeconds: number | null;
  cpuTotal: number | null;
  cpuIdle: number | null;
  memoryTotal: number | null;
  memoryAvailable: number | null;
  memoryCached: number | null;
  memoryBuffers: number | null;
  diskReadBytes: number | null;
  diskWriteBytes: number | null;
  filesystems:
    | {
        source: string;
        mount: string;
        totalKib: number;
        usedKib: number;
        availableKib: number;
        usePercent: number;
      }[]
    | null;
  networkInterfaces:
    | {
        name: string;
        receivedBytes: number;
        receivedErrors: number;
        receivedDropped: number;
        sentBytes: number;
        sentErrors: number;
        sentDropped: number;
      }[]
    | null;
};

export type ResourceMetrics = {
  sample: SshResourceSample;
  cpu: number | null;
  rxRate: number | null;
  txRate: number | null;
  diskReadRate: number | null;
  diskWriteRate: number | null;
  perIfaceRates: Map<string, { rx: number | null; tx: number | null }>;
};

function deltaRate(current: number, previous: number, seconds: number): number {
  return Math.max(0, current - previous) / seconds;
}

/** Derive rates using the remote uptime counter, so buffered SSH frames don't
 * create artificial spikes when the webview receives them together. */
export function deriveResourceMetrics(
  current: SshResourceSample,
  previous: SshResourceSample | null,
): ResourceMetrics {
  const sample: SshResourceSample = {
    ...current,
    hostname: current.hostname ?? previous?.hostname ?? null,
    version: current.version ?? previous?.version ?? null,
    filesystems: current.filesystems ?? previous?.filesystems ?? null,
  };
  const elapsed =
    sample.uptimeSeconds !== null && previous?.uptimeSeconds !== null && previous
      ? sample.uptimeSeconds - previous.uptimeSeconds
      : 0;
  const cpuTotalDelta =
    sample.cpuTotal !== null && previous?.cpuTotal !== null && previous
      ? sample.cpuTotal - previous.cpuTotal
      : 0;
  const cpuIdleDelta =
    sample.cpuIdle !== null && previous?.cpuIdle !== null && previous
      ? sample.cpuIdle - previous.cpuIdle
      : 0;
  const canRate = elapsed > 0 && Number.isFinite(elapsed);
  const previousInterfaces = new Map(
    (previous?.networkInterfaces ?? []).map((iface) => [iface.name, iface]),
  );
  const perIfaceRates = new Map<string, { rx: number | null; tx: number | null }>();
  for (const iface of sample.networkInterfaces ?? []) {
    const prior = previousInterfaces.get(iface.name);
    perIfaceRates.set(iface.name, {
      rx: canRate && prior ? deltaRate(iface.receivedBytes, prior.receivedBytes, elapsed) : null,
      tx: canRate && prior ? deltaRate(iface.sentBytes, prior.sentBytes, elapsed) : null,
    });
  }
  const ifaceRates = [...perIfaceRates.values()];
  const rxRate =
    canRate && ifaceRates.length > 0 && ifaceRates.every((rate) => rate.rx !== null)
      ? ifaceRates.reduce((sum, rate) => sum + (rate.rx ?? 0), 0)
      : null;
  const txRate =
    canRate && ifaceRates.length > 0 && ifaceRates.every((rate) => rate.tx !== null)
      ? ifaceRates.reduce((sum, rate) => sum + (rate.tx ?? 0), 0)
      : null;
  return {
    sample,
    cpu:
      sample.cpuTotal !== null && sample.cpuIdle !== null && previous && cpuTotalDelta > 0
        ? Math.max(0, Math.min(100, (1 - cpuIdleDelta / cpuTotalDelta) * 100))
        : null,
    rxRate,
    txRate,
    diskReadRate:
      canRate && sample.diskReadBytes !== null && previous?.diskReadBytes !== null && previous
        ? deltaRate(sample.diskReadBytes, previous.diskReadBytes, elapsed)
        : null,
    diskWriteRate:
      canRate && sample.diskWriteBytes !== null && previous?.diskWriteBytes !== null && previous
        ? deltaRate(sample.diskWriteBytes, previous.diskWriteBytes, elapsed)
        : null,
    perIfaceRates,
  };
}
