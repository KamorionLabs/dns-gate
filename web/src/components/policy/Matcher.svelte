<script lang="ts">
  import type { SubjectMatcher } from '../../lib/types';
  let { m }: { m: SubjectMatcher } = $props();
  const claims = $derived(Object.entries(m.claims ?? {}));
</script>

<span class="matcher mono">
  <span class="iss">{m.issuer}</span>
  {#each claims as [k, vs] (k)}
    <span class="claim"><span class="k">{k}</span><span class="eq">=</span>{#each vs as v, i (v)}{#if i}<span class="or">|</span>{/if}<span class="v">{v}</span>{/each}</span>
  {:else}
    <span class="any">any token</span>
  {/each}
</span>

<style>
  .matcher {
    display: inline-flex;
    flex-wrap: wrap;
    align-items: baseline;
    gap: 2px 8px;
    font-size: 12px;
    min-width: 0;
  }
  .iss {
    padding: 0 5px;
    border-radius: 3px;
    background: var(--rule-soft);
    color: var(--ink-2);
    font-weight: 600;
  }
  .claim {
    overflow-wrap: anywhere;
  }
  .k {
    color: var(--ink-3);
  }
  .eq,
  .or {
    color: var(--ink-4);
    padding: 0 2px;
  }
  .v {
    color: var(--ink);
  }
  .any {
    color: var(--brass);
  }
</style>
