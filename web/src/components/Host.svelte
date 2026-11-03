<script lang="ts">
  import { fqdn, shortHashes } from '../lib/format';
  // short: long hash labels are shortened in the middle (tables).
  let { host, zone, showZone = true, short = false }: { host: string; zone: string; showZone?: boolean; short?: boolean } = $props();
  const parts = $derived(fqdn(short ? shortHashes(host) : host, zone));
</script>

<span class="host mono"><span class="label" class:apex={parts.name === '@'}>{parts.name}</span>{#if showZone}<span class="suffix">{parts.name === '@' ? ' ' + parts.suffix : parts.suffix}</span>{/if}</span>

<style>
  .host {
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    min-width: 0;
  }
  .label {
    color: var(--ink);
    font-weight: 500;
  }
  .apex {
    color: var(--seal-ink);
  }
  .suffix {
    color: var(--ink-4);
  }
</style>
