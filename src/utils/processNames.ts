import type { ProcessTraffic, SocketStream } from '../types';

const KNOWN_PROCESS_NAMES: Record<string, string> = {
  'chrome.exe': 'Google Chrome',
  'msedge.exe': 'Microsoft Edge',
  'msedgewebview2.exe': 'Edge WebView2',
  'discord.exe': 'Discord',
  'steam.exe': 'Steam',
  'steamwebhelper.exe': 'Steam Web Helper',
  'spotify.exe': 'Spotify',
  'code.exe': 'Visual Studio Code',
  'slack.exe': 'Slack',
  'telegram.exe': 'Telegram',
  'firefox.exe': 'Mozilla Firefox',
  'brave.exe': 'Brave Browser',
  'opera.exe': 'Opera',
  'obs64.exe': 'OBS Studio',
  'explorer.exe': 'Windows Explorer',
  'svchost.exe': 'Host Process (svchost)',
  'searchhost.exe': 'Windows Search',
  'startmenuexperiencehost.exe': 'Start Menu',
  'taskhostw.exe': 'Task Host',
  'runtimebroker.exe': 'Runtime Broker',
  'language_server.exe': 'Language Server',
  'powershell.exe': 'PowerShell',
  'pwsh.exe': 'PowerShell 7',
  'cmd.exe': 'Command Prompt',
  'glassnet.exe': 'GlassNet',
  'system': 'Windows System Kernel',
  'system idle process': 'System Idle',
  'ntoskrnl.exe': 'Windows Kernel',
  'conhost.exe': 'Console Host',
  'taskmgr.exe': 'Task Manager',
};

export function getFriendlyProcessName(rawName: string): string {
  if (!rawName) return 'Unknown Application';
  const lower = rawName.toLowerCase().trim();

  if (KNOWN_PROCESS_NAMES[lower]) {
    return KNOWN_PROCESS_NAMES[lower];
  }

  // If it's "PID: 1234", leave it readable
  if (rawName.startsWith('PID:')) {
    return rawName;
  }

  // Strip .exe
  let clean = rawName;
  if (clean.toLowerCase().endsWith('.exe')) {
    clean = clean.slice(0, -4);
  }

  // Replace underscores and hyphens with spaces
  clean = clean.replace(/[-_]+/g, ' ').trim();

  // Capitalize words
  clean = clean
    .split(' ')
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');

  return clean;
}

export interface GroupedProcess {
  groupKey: string;
  name: string; // original raw process name (e.g. chrome.exe)
  displayName: string; // friendly name (e.g. Google Chrome)
  primaryPid: number;
  pids: number[];
  path: string;
  icon_data_url: string | null;
  download_speed_bps: number;
  upload_speed_bps: number;
  active_sockets_count: number;
  is_blocked: boolean;
  is_system: boolean;
  has_external_traffic: boolean;
  has_unencrypted_traffic: boolean;
  sockets: SocketStream[];
  subProcesses: ProcessTraffic[];
}

export function groupProcesses(processes: ProcessTraffic[]): GroupedProcess[] {
  const groups = new Map<string, GroupedProcess>();

  for (const proc of processes) {
    // Generate unique group key based on executable name or path
    const key = (proc.path || proc.name).toLowerCase();

    if (!groups.has(key)) {
      groups.set(key, {
        groupKey: key,
        name: proc.name,
        displayName: getFriendlyProcessName(proc.name),
        primaryPid: proc.pid,
        pids: [proc.pid],
        path: proc.path,
        icon_data_url: proc.icon_data_url || null,
        download_speed_bps: proc.download_speed_bps,
        upload_speed_bps: proc.upload_speed_bps,
        active_sockets_count: proc.active_sockets_count,
        is_blocked: proc.is_blocked,
        is_system: proc.is_system,
        has_external_traffic: proc.has_external_traffic,
        has_unencrypted_traffic: proc.has_unencrypted_traffic,
        sockets: [...proc.sockets],
        subProcesses: [proc],
      });
    } else {
      const g = groups.get(key)!;
      g.pids.push(proc.pid);
      if (!g.icon_data_url && proc.icon_data_url) {
        g.icon_data_url = proc.icon_data_url || null;
      }
      if (!g.path && proc.path) {
        g.path = proc.path;
      }
      g.download_speed_bps += proc.download_speed_bps;
      g.upload_speed_bps += proc.upload_speed_bps;
      g.active_sockets_count += proc.active_sockets_count;
      g.is_blocked = g.is_blocked || proc.is_blocked;
      g.has_external_traffic = g.has_external_traffic || proc.has_external_traffic;
      g.has_unencrypted_traffic = g.has_unencrypted_traffic || proc.has_unencrypted_traffic;
      g.sockets.push(...proc.sockets);
      g.subProcesses.push(proc);
    }
  }

  // Sort groups: highest total bandwidth first, then socket count
  const result = Array.from(groups.values());
  result.sort((a, b) => {
    const totalA = a.download_speed_bps + a.upload_speed_bps;
    const totalB = b.download_speed_bps + b.upload_speed_bps;
    if (totalB !== totalA) {
      return totalB - totalA;
    }
    return b.active_sockets_count - a.active_sockets_count;
  });

  return result;
}
