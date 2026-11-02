<script lang="ts">
  import type { ZoneSummary } from '../lib/types';
  let { z, height = 8 }: { z: ZoneSummary; height?: number } = $props();
  const total = $derived(Math.max(z.rrsets, 1));
  const segs = $derived(
    [
      { k: 'managed', n: z.managed },
      { k: 'pending', n: z.pending },
      { k: 'tainted', n: z.tainted },
      { k: 'foreign', n: z.foreign },
    ].filter((s) => s.n > 0),
  );
</script>

<div class="strip" style:height="{height}px" role="img" aria-label="{z.managed} managed, {z.pending} pending, {z.tainted} drifted, {z.foreign} foreign of {z.rrsets} record sets">
  {#each segs as s (s.k)}
    <span class="seg {s.k}" style:flex-grow={s.n / total}></span>
  {/each}
</div>

<style>
  .strip {
    display: flex;
    gap: 2px;
    width: 100%;
    border-radius: 999px;
    overflow: hidden;
    background: var(--rule-soft);
  }
  .seg {
    flex-basis: 0;
    min-width: 6px;
  }
  .managed {
    background: var(--seal-ink);
  }
  .pending {
    background: var(--brass);
  }
  .tainted {
    background: var(--wax);
  }
  .foreign {
    background: repeating-linear-gradient(135deg, var(--pencil-wash) 0 3px, transparent 3px 6px), var(--rule-soft);
    box-shadow: inset 0 0 0 1px var(--rule);
  }
</style>
