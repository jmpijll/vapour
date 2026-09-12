export function formatSpeed(bytesPerSec: number): { value: string; unit: string } {
  if (bytesPerSec <= 0) {
    return { value: '0', unit: 'B/s' };
  }
  const units = ['B/s', 'KB/s', 'MB/s', 'GB/s'];
  let i = 0;
  let val = bytesPerSec;
  while (val >= 1024 && i < units.length - 1) {
    val /= 1024;
    i++;
  }
  return {
    value: val < 10 && i > 0 ? val.toFixed(1) : Math.round(val).toString(),
    unit: units[i],
  };
}

export function countryCodeToFlag(code?: string | null): string {
  if (!code || code === 'LAN' || code === 'WW') return '🌐';
  if (code === 'EU') return '🇪🇺';
  if (code === 'AP') return '🌏';
  if (code.length !== 2) return '🌐';

  // Regional Indicator Symbol letters
  const codePoints = code
    .toUpperCase()
    .split('')
    .map((char) => 127397 + char.charCodeAt(0));
  return String.fromCodePoint(...codePoints);
}

export function getProviderColor(provider?: string | null): string {
  if (!provider) return 'bg-slate-700/40 text-slate-300';
  const p = provider.toLowerCase();
  if (p.includes('cloudflare')) return 'bg-amber-500/20 text-amber-300 border-amber-500/30';
  if (p.includes('google')) return 'bg-blue-500/20 text-blue-300 border-blue-500/30';
  if (p.includes('azure') || p.includes('microsoft')) return 'bg-sky-500/20 text-sky-300 border-sky-500/30';
  if (p.includes('amazon') || p.includes('aws')) return 'bg-orange-500/20 text-orange-300 border-orange-500/30';
  if (p.includes('steam') || p.includes('valve')) return 'bg-indigo-500/20 text-indigo-300 border-indigo-500/30';
  if (p.includes('discord')) return 'bg-purple-500/20 text-purple-300 border-purple-500/30';
  if (p.includes('local') || p.includes('lan')) return 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30';
  return 'bg-slate-500/20 text-slate-300 border-slate-500/30';
}
