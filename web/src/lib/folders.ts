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

/** Whether a rule applies to the zone: its zones match it, or its folders the folder of the zone. */
export function ruleCovers(r: { zones?: string[] | null; folders?: string[] | null }, zone: string): boolean {
  if ((r.zones ?? []).some((z) => zoneMatch(z, zone))) return true;
  const f = folderOf(zone);
  return !!f && (r.folders ?? []).some((p) => folderMatch(p, f));
}

/** Whether a folder is the selected folder or one of its subfolders ("/" selects the root only). */
export function inFolder(selected: string, folder: string | undefined): boolean {
  if (!selected) return true;
  if (!folder) return false;
  if (selected === '/') return folder === '/';
  return folder === selected || folder.startsWith(selected + '/');
}

/** The folders of the zones and their parents, sorted, for a folder filter. */
export function folderOptions(zones: { folder?: string }[]): string[] {
  const out = new Set<string>();
  for (const z of zones) {
    if (!z.folder) continue;
    if (z.folder === '/') {
      out.add('/');
      continue;
    }
    const parts = z.folder.split('/').filter(Boolean);
    for (let i = 1; i <= parts.length; i++) out.add('/' + parts.slice(0, i).join('/'));
  }
  return [...out].sort((a, b) => a.localeCompare(b));
}
