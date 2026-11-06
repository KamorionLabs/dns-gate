// Provider folders of the zones (EuroDNS), as last read from the gate, so the
// console can apply the folder selectors of the rules the way the gate does.
// The map is reactive: rights derived from it update once a folder is known.
import { SvelteMap } from 'svelte/reactivity';
import { folderMatch, zoneMatch } from './glob';

const known = new SvelteMap<string, string>();

/** Records the folders of zones read from the gate (zone list, inventory). */
export function rememberFolders(zones: { zone: string; folder?: string }[]): void {
  for (const z of zones) {
    if (z.folder && known.get(z.zone) !== z.folder) known.set(z.zone, z.folder);
    else if (!z.folder && known.has(z.zone)) known.delete(z.zone);
  }
}

/** Folder of a zone as last read, "" when unknown or without folders. */
export const folderOf = (zone: string): string => known.get(zone) ?? '';

/**
 * Whether a rule applies to the zone: its zones match it, or its folders the
 * folder of the zone and, when set, its folder_zones the zone (the bounds of
 * a managed or delegated rule).
 */
export function ruleCovers(
  r: { zones?: string[] | null; folders?: string[] | null; folder_zones?: string[] | null },
  zone: string,
): boolean {
  if ((r.zones ?? []).some((z) => zoneMatch(z, zone))) return true;
  const f = folderOf(zone);
  if (!f || !(r.folders ?? []).some((p) => folderMatch(p, f))) return false;
  return !r.folder_zones?.length || r.folder_zones.some((z) => zoneMatch(z, zone));
}

/** Whether a zone folder matches the folder glob of the filter (as ?folder= of the API); no filter keeps every zone. */
export function inFolder(glob: string, folder: string | undefined): boolean {
  return !glob || folderMatch(glob, folder ?? '');
}

/**
 * Folder globs for a folder filter, sorted: each folder of the zones (only
 * that folder) and, for each folder with subfolders, "<folder>/**" (every
 * folder below it, as the API reads it).
 */
export function folderOptions(zones: { folder?: string }[]): string[] {
  const out = new Set<string>();
  for (const z of zones) {
    if (!z.folder) continue;
    out.add(z.folder);
    if (z.folder === '/') continue;
    const parts = z.folder.split('/').filter(Boolean);
    for (let i = 0; i < parts.length; i++) out.add('/' + parts.slice(0, i).join('/') + (i ? '/' : '') + '**');
  }
  return [...out].sort((a, b) => a.localeCompare(b));
}

/** Label of a folder glob in the filter. */
export function folderLabel(glob: string): string {
  if (glob === '/') return '/ (no folder)';
  if (glob === '/**') return '/** (every folder)';
  if (glob.endsWith('/**')) return `${glob} (below ${glob.slice(0, -3)})`;
  return glob;
}
