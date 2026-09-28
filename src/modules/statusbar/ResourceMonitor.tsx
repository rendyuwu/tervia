import { useEffect, useState } from "react";
import { cn } from "@/lib/utils";
import { formatBytes } from "@/lib/format";
import { Activity, Clock, Cpu, HardDrive, MemoryStick, Server, Timer } from "lucide-react";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import {
  startSshResourceStream,
  stopSshResourceStream,
  type SshResourceStreamEvent,
  type SshResourceStreamStart,
} from "@/modules/ssh/bridge";
import {
  deriveResourceMetrics,
  type ResourceMetrics,
  type SshResourceSample,
} from "./resourceMetrics";

type Metrics = ResourceMetrics;

const pendingResourceStreamStarts = new Map<number, Promise<void>>();

async function startQueuedResourceStream(
  sessionId: number,
  onEvent: (event: SshResourceStreamEvent) => void,
  isActive: () => boolean,
): Promise<SshResourceStreamStart | null> {
  const previous = pendingResourceStreamStarts.get(sessionId) ?? Promise.resolve();
  let release!: () => void;
  const current = new Promise<void>((resolve) => {
    release = resolve;
  });
  pendingResourceStreamStarts.set(sessionId, current);
  await previous.catch(() => undefined);
  try {
    if (!isActive()) return null;
    const result = await startSshResourceStream(sessionId, onEvent);
    if (!isActive()) {
      await stopSshResourceStream(sessionId, result.streamId).catch(() => undefined);
      return null;
    }
    return result;
  } finally {
    release();
    if (pendingResourceStreamStarts.get(sessionId) === current) {
      pendingResourceStreamStarts.delete(sessionId);
    }
  }
}

function formatNetwork(bytesPerSecond: number | null): string {
  return bytesPerSecond === null
    ? "Unavailable"
    : `${((bytesPerSecond * 8) / 1_000_000).toFixed(2)} Mb/s`;
}

function formatNetworkCompact(bytesPerSecond: number | null): string {
  if (bytesPerSecond === null) return "N/A";
  const bitsPerSecond = bytesPerSecond * 8;
  if (bitsPerSecond < 100_000) return `${Math.round(bitsPerSecond / 1000)}K`;
  if (bitsPerSecond < 1_000_000) return `${(bitsPerSecond / 1000).toFixed(1)}K`;
  return `${(bitsPerSecond / 1_000_000).toFixed(bitsPerSecond < 10_000_000 ? 2 : 1)}M`;
}

function mebibytes(kib: number | null): string {
  return kib === null ? "N/A" : `${Math.round(kib / 1024)} MiB`;
}

function memoryUsed(metrics: Metrics | null): number | null {
  const { memoryTotal, memoryAvailable } = metrics?.sample ?? {};
  return memoryTotal != null && memoryAvailable != null
    ? Math.max(0, memoryTotal - memoryAvailable)
    : null;
}

function compactFilesystemSizePair(usedKib: number, totalKib: number): string {
  return `${(usedKib / 1_048_576).toFixed(1)}/${(totalKib / 1_048_576).toFixed(1)} GiB`;
}

function formatUptime(seconds: number): string {
  const total = Math.floor(seconds);
  const days = Math.floor(total / 86_400);
  const hours = Math.floor((total % 86_400) / 3_600);
  const minutes = Math.floor((total % 3_600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  if (minutes > 0) return `${minutes}m ${total % 60}s`;
  return `${total}s`;
}

function Segment({
  children,
  title,
  tooltip,
  tooltipClassName = "",
  className = "",
  grow = false,
}: {
  children: React.ReactNode;
  title?: string;
  tooltip?: React.ReactNode;
  tooltipClassName?: string;
  className?: string;
  grow?: boolean;
}) {
  const segment = (
    <span
      title={tooltip ? undefined : title}
      tabIndex={tooltip ? 0 : undefined}
      className={cn(
        "border-border/60 inline-flex h-5 items-center gap-1 border-r px-1.5 whitespace-nowrap last:border-r-0",
        grow ? "min-w-0 flex-1 overflow-hidden" : "shrink-0",
        className,
      )}
    >
      {children}
    </span>
  );
  if (!tooltip) return segment;
  return (
    <Tooltip>
      <TooltipTrigger asChild>{segment}</TooltipTrigger>
      <TooltipContent side="top" align="start" className={tooltipClassName}>
        {tooltip}
      </TooltipContent>
    </Tooltip>
  );
}

function UsageGauge({ value }: { value: number | null }) {
  const percent = value === null ? 0 : Math.max(0, Math.min(100, value));
  return (
    <span className="bg-muted/80 h-1 w-5 shrink-0 overflow-hidden rounded-full" aria-hidden="true">
      <span
        className="bg-primary block h-full rounded-full transition-[width] duration-300"
        style={{ width: `${percent}%`, opacity: value === null ? 0.35 : 1 }}
      />
    </span>
  );
}

function MemoryDetails({ metrics }: { metrics: Metrics | null }) {
  const sample = metrics?.sample;
  const used = memoryUsed(metrics);
  const rows = metrics
    ? [
        ["Total RAM", mebibytes(sample?.memoryTotal ?? null)],
        ["Used RAM", mebibytes(used)],
        ["Available RAM", mebibytes(sample?.memoryAvailable ?? null)],
        ["Cached RAM", mebibytes(sample?.memoryCached ?? null)],
        ["Buffers", mebibytes(sample?.memoryBuffers ?? null)],
      ]
    : [["Memory details", "waiting for sample"]];
  return (
    <div className="min-w-44 space-y-0.5 font-mono text-[10px]">
      {rows.map(([label, value]) => (
        <div key={label} className="grid grid-cols-[1fr_auto] gap-x-4">
          <span className="text-muted-foreground">{label}:</span>
          <span className="text-foreground text-right">{value}</span>
        </div>
      ))}
    </div>
  );
}

function NetworkDetails({ metrics }: { metrics: Metrics | null }) {
  const networkInterfaces = metrics?.sample.networkInterfaces;
  if (!networkInterfaces?.length) {
    return <span className="font-mono text-[10px]">Network counters unavailable.</span>;
  }
  return (
    <div className="max-w-[min(560px,calc(100vw-32px))] space-y-2 font-mono text-[10px]">
      <div className="text-muted-foreground">
        Physical interface counters (virtual interfaces excluded)
      </div>
      {networkInterfaces.map((iface) => {
        const rates = metrics?.perIfaceRates.get(iface.name);
        return (
          <div key={iface.name}>
            <div className="text-foreground mb-0.5 font-semibold">{iface.name}</div>
            <div className="grid grid-cols-[44px_1fr_1fr_42px_48px] gap-x-2">
              <span />
              <span className="text-muted-foreground text-right">Total</span>
              <span className="text-muted-foreground text-right">Rate</span>
              <span className="text-muted-foreground text-right">Errors</span>
              <span className="text-muted-foreground text-right">Dropped</span>
              <span className="text-diff-added">↓ In</span>
              <span className="text-foreground text-right">{formatBytes(iface.receivedBytes)}</span>
              <span className="text-foreground text-right">{formatNetwork(rates?.rx ?? null)}</span>
              <span className="text-foreground text-right">{iface.receivedErrors}</span>
              <span className="text-foreground text-right">{iface.receivedDropped}</span>
              <span className="text-info">↑ Out</span>
              <span className="text-foreground text-right">{formatBytes(iface.sentBytes)}</span>
              <span className="text-foreground text-right">{formatNetwork(rates?.tx ?? null)}</span>
              <span className="text-foreground text-right">{iface.sentErrors}</span>
              <span className="text-foreground text-right">{iface.sentDropped}</span>
            </div>
          </div>
        );
      })}
    </div>
  );
}

function FilesystemDetails({ filesystems }: { filesystems: SshResourceSample["filesystems"] }) {
  return (
    <div className="max-h-[min(65vh,540px)] w-[min(760px,calc(100vw-32px))] max-w-[calc(100vw-32px)] overflow-auto font-mono text-[10px]">
      <table className="w-full min-w-[600px] border-collapse text-left">
        <thead className="text-muted-foreground bg-popover sticky top-0">
          <tr>
            <th className="px-2 py-1 font-medium">Filesystem</th>
            <th className="px-2 py-1 text-right font-medium">1K-blocks</th>
            <th className="px-2 py-1 text-right font-medium">Used</th>
            <th className="px-2 py-1 text-right font-medium">Available</th>
            <th className="px-2 py-1 text-right font-medium">Use%</th>
            <th className="px-2 py-1 font-medium">Mounted on</th>
          </tr>
        </thead>
        <tbody>
          {filesystems?.map((fs, index) => (
            <tr key={`${fs.mount}:${fs.source}:${index}`} className="border-border/40 border-t">
              <td className="text-foreground max-w-48 truncate px-2 py-0.5" title={fs.source}>
                {fs.source}
              </td>
              <td className="text-foreground px-2 py-0.5 text-right">
                {formatBytes(fs.totalKib * 1024)}
              </td>
              <td className="text-foreground px-2 py-0.5 text-right">
                {formatBytes(fs.usedKib * 1024)}
              </td>
              <td className="text-foreground px-2 py-0.5 text-right">
                {formatBytes(fs.availableKib * 1024)}
              </td>
              <td className="text-foreground px-2 py-0.5 text-right">{fs.usePercent}%</td>
              <td className="text-foreground max-w-64 truncate px-2 py-0.5" title={fs.mount}>
                {fs.mount}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {!filesystems?.length && (
        <div className="text-muted-foreground px-2 py-1">Filesystem data is not available yet.</div>
      )}
    </div>
  );
}

type StreamStatus = "connecting" | "live" | "stale" | "unavailable";

/** Optional SSH telemetry strip; platform and ping limits are in
 * `KNOWN-LIMITS.md`. */
export function SshResourceBar({ sessionId }: { sessionId: number }) {
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [streamStatus, setStreamStatus] = useState<StreamStatus>("connecting");
  const [streamError, setStreamError] = useState<string | null>(null);
  const [ping, setPing] = useState<{ host: string; latencyMs: number | null } | null>(null);
  const [pingEnabled, setPingEnabled] = useState(true);
  const primaryFilesystem =
    metrics?.sample.filesystems?.find((fs) => fs.mount === "/") ?? metrics?.sample.filesystems?.[0];

  useEffect(() => {
    let active = true;
    let previous: SshResourceSample | null = null;
    let streamId: number | null = null;
    let retryAttempt = 0;
    let retryTimer: ReturnType<typeof setTimeout> | undefined;
    let staleTimer: ReturnType<typeof setTimeout> | undefined;
    setMetrics(null);
    setStreamStatus("connecting");
    setStreamError(null);
    setPing(null);
    setPingEnabled(true);

    const scheduleRetry = () => {
      if (!active || retryTimer || !previous) return;
      const delay = Math.min(3000 * 2 ** retryAttempt, 30_000);
      retryAttempt++;
      retryTimer = setTimeout(() => {
        retryTimer = undefined;
        if (active) void start();
      }, delay);
    };
    const handleEvent = (event: SshResourceStreamEvent) => {
      if (!active) return;
      if (event.type === "ping") {
        setPing({ host: event.host, latencyMs: event.latencyMs });
        return;
      }
      if (event.type === "error") {
        if (staleTimer) {
          clearTimeout(staleTimer);
          staleTimer = undefined;
        }
        setStreamError(event.message);
        if (previous) {
          setStreamStatus("stale");
          scheduleRetry();
        } else {
          setStreamStatus("unavailable");
        }
        return;
      }
      const nextMetrics = deriveResourceMetrics(event.sample, previous);
      setMetrics(nextMetrics);
      previous = nextMetrics.sample;
      retryAttempt = 0;
      setStreamError(null);
      setStreamStatus("live");
      if (staleTimer) clearTimeout(staleTimer);
      staleTimer = setTimeout(() => {
        if (active) setStreamStatus("stale");
      }, 8000);
    };
    const start = async () => {
      if (!active) return;
      setStreamStatus((status) => (status === "live" ? "stale" : "connecting"));
      try {
        const result = await startQueuedResourceStream(sessionId, handleEvent, () => active);
        if (!result || !active) return;
        streamId = result.streamId;
        setPingEnabled(result.pingEnabled);
      } catch (cause) {
        if (!active) return;
        setStreamError(cause instanceof Error ? cause.message : String(cause));
        if (previous) {
          setStreamStatus("stale");
          scheduleRetry();
        } else {
          setStreamStatus("unavailable");
        }
      }
    };
    void start();

    return () => {
      active = false;
      if (retryTimer) clearTimeout(retryTimer);
      if (staleTimer) clearTimeout(staleTimer);
      if (streamId !== null) void stopSshResourceStream(sessionId, streamId).catch(() => undefined);
    };
  }, [sessionId]);

  const statusLabel =
    streamStatus === "live"
      ? "Live"
      : streamStatus === "stale"
        ? "Stale"
        : streamStatus === "unavailable"
          ? "Unavailable"
          : "Connecting";

  return (
    <div
      role="group"
      aria-label="Remote system resource metrics"
      title={
        streamError ??
        `Remote metrics ${statusLabel.toLowerCase()}; samples arrive about once per second`
      }
      className="text-muted-foreground flex min-w-0 flex-1 items-center overflow-hidden text-[10px] tabular-nums"
    >
      <Segment
        title="Remote host"
        tooltip={
          <div className="max-w-[min(720px,calc(100vw-32px))] space-y-1 font-mono text-[10px] break-words whitespace-pre-wrap">
            <div>
              <span className="text-muted-foreground">Host: </span>
              <span className="text-foreground">{metrics?.sample.hostname ?? "Unavailable"}</span>
            </div>
            <div>
              <span className="text-muted-foreground">Version: </span>
              <span className="text-foreground">{metrics?.sample.version ?? "Unavailable"}</span>
            </div>
            <div>
              <span className="text-muted-foreground">Monitor: </span>
              <span className="text-foreground">{statusLabel}</span>
            </div>
            {streamError && <div className="text-destructive">{streamError}</div>}
          </div>
        }
        tooltipClassName="max-w-[min(720px,calc(100vw-32px))] whitespace-normal"
        className="pl-1"
      >
        <Server size={12} className="shrink-0" />
        <span
          aria-hidden="true"
          className={cn(
            "size-1.5 shrink-0 rounded-full",
            streamStatus === "live" ? "bg-icon-done" : "bg-muted-foreground/50",
          )}
        />
        <span className="text-foreground max-w-20 truncate font-medium">
          {metrics?.sample.hostname ?? "SSH"}
        </span>
      </Segment>
      {streamStatus !== "live" && (
        <Segment title={streamError ?? statusLabel} className="text-destructive">
          {streamStatus === "stale" ? "STALE" : streamStatus === "unavailable" ? "N/A" : "…"}
        </Segment>
      )}
      <Segment
        title="CPU usage"
        tooltip={
          <span className="font-mono text-[10px]">
            Current CPU load: {metrics?.cpu == null ? "Unavailable" : `${metrics.cpu.toFixed(0)}%`}
          </span>
        }
      >
        <Cpu size={12} className="shrink-0" />
        <span className="text-muted-foreground text-[9px] font-medium">CPU</span>
        <span className="text-foreground min-w-[2.5ch] text-right font-medium">
          {metrics?.cpu == null ? "N/A" : `${metrics.cpu.toFixed(0)}%`}
        </span>
        <UsageGauge value={metrics?.cpu ?? null} />
      </Segment>
      <Segment title="Memory details" tooltip={<MemoryDetails metrics={metrics} />}>
        <MemoryStick size={12} className="shrink-0" />
        <span className="text-muted-foreground text-[9px] font-medium">RAM</span>
        <span className="text-foreground font-medium">
          {memoryUsed(metrics) !== null && metrics?.sample.memoryTotal != null
            ? `${(memoryUsed(metrics)! / 1_048_576).toFixed(2)}/${(metrics.sample.memoryTotal / 1_048_576).toFixed(2)} GiB`
            : "N/A"}
        </span>
        <UsageGauge
          value={
            memoryUsed(metrics) !== null &&
            metrics?.sample.memoryTotal != null &&
            metrics.sample.memoryTotal > 0
              ? (memoryUsed(metrics)! / metrics.sample.memoryTotal) * 100
              : null
          }
        />
      </Segment>
      <Segment
        title="Network throughput and per-interface counters"
        tooltip={<NetworkDetails metrics={metrics} />}
        tooltipClassName="max-w-[min(560px,calc(100vw-32px))] whitespace-normal"
      >
        <Activity size={12} className="shrink-0" />
        <span className="text-muted-foreground text-[9px] font-medium">NET</span>
        <span className="text-foreground inline-flex items-center gap-1 font-medium">
          <span className="text-diff-added">↓</span>
          {formatNetworkCompact(metrics?.rxRate ?? null)}
          <span className="text-info">↑</span>
          {formatNetworkCompact(metrics?.txRate ?? null)}
        </span>
      </Segment>
      <Segment
        title="Disk read and write throughput"
        tooltip={
          <div className="space-y-0.5 font-mono text-[10px]">
            <div>
              Read:{" "}
              {metrics?.diskReadRate == null
                ? "Unavailable"
                : `${formatBytes(metrics.diskReadRate)}/s`}
            </div>
            <div>
              Written:{" "}
              {metrics?.diskWriteRate == null
                ? "Unavailable"
                : `${formatBytes(metrics.diskWriteRate)}/s`}
            </div>
            <div className="text-muted-foreground">Physical Linux block device counters.</div>
          </div>
        }
      >
        <HardDrive size={12} className="shrink-0" />
        <span className="text-muted-foreground text-[9px] font-medium">IO</span>
        <span className="inline-flex items-center gap-1 font-medium">
          <span className="text-diff-added">↓</span>
          {metrics?.diskReadRate == null ? "N/A" : formatBytes(metrics.diskReadRate)}
          <span className="text-info">↑</span>
          {metrics?.diskWriteRate == null ? "N/A" : formatBytes(metrics.diskWriteRate)}
        </span>
      </Segment>
      <Segment
        title="Local ping to SSH server"
        tooltip={
          <div className="space-y-0.5 font-mono text-[10px]">
            <div>
              Local ICMP ping to {ping?.host ?? "the SSH server"}:{" "}
              {!pingEnabled
                ? "skipped for ProxyJump"
                : ping
                  ? ping.latencyMs === null
                    ? "no reply"
                    : `${ping.latencyMs < 1 ? "<1" : ping.latencyMs.toFixed(ping.latencyMs < 10 ? 1 : 0)} ms`
                  : "waiting for first ping"}
            </div>
            <div className="text-muted-foreground">
              Measured from this computer. No reply can mean ICMP is blocked. ProxyJump connections
              skip local ping so the final hop name is not resolved on this network.
            </div>
          </div>
        }
      >
        <Timer size={12} className="shrink-0" />
        <span className="text-muted-foreground text-[9px] font-medium">PING</span>
        <span className="text-foreground font-medium">
          {!pingEnabled
            ? "N/A"
            : ping
              ? ping.latencyMs === null
                ? "N/A"
                : `${ping.latencyMs < 1 ? "<1" : ping.latencyMs.toFixed(ping.latencyMs < 10 ? 1 : 0)}ms`
              : "…"}
        </span>
      </Segment>
      <Segment
        title="Remote host uptime"
        tooltip={
          <div className="space-y-0.5 font-mono text-[10px]">
            <div>
              Uptime:{" "}
              {metrics?.sample.uptimeSeconds != null
                ? `${metrics.sample.uptimeSeconds.toFixed(2)} sec`
                : "Unavailable"}
            </div>
            <div className="text-muted-foreground">
              Samples arrive about once per second over a persistent SSH channel.
            </div>
          </div>
        }
      >
        <Clock size={12} className="shrink-0" />
        <span className="text-muted-foreground text-[9px] font-medium">UP</span>
        <span className="text-foreground font-medium">
          {metrics?.sample.uptimeSeconds != null
            ? formatUptime(metrics.sample.uptimeSeconds)
            : "N/A"}
        </span>
      </Segment>
      <Segment
        title="Root filesystem usage"
        tooltip={<FilesystemDetails filesystems={metrics?.sample.filesystems ?? null} />}
        tooltipClassName="max-w-[calc(100vw-24px)] p-2"
        grow
        className="border-r-0"
      >
        <HardDrive size={12} className="shrink-0" />
        <span className="text-muted-foreground text-[9px] font-medium">FS</span>
        <span className="flex min-w-0 items-center gap-1 overflow-hidden">
          {primaryFilesystem ? (
            <>
              <span className="text-muted-foreground max-w-12 truncate">
                {primaryFilesystem.mount}
              </span>
              <span className="text-foreground font-medium">{primaryFilesystem.usePercent}%</span>
              <span className="text-foreground/75">
                {compactFilesystemSizePair(primaryFilesystem.usedKib, primaryFilesystem.totalKib)}
              </span>
            </>
          ) : (
            <span>N/A</span>
          )}
        </span>
      </Segment>
    </div>
  );
}
