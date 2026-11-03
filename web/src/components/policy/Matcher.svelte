<script lang="ts">
  import type { SubjectMatcher } from '../../lib/types';
  import { pipelineName, serviceConnectionName } from '../../lib/identity';
  let { m }: { m: SubjectMatcher } = $props();
  // Readable form of a pipeline subject value, next to the raw pattern.
  const readable = (v: string) => {
    const sc = serviceConnectionName(v);
    return sc ? `Pipeline · ${sc}` : pipelineName(v);
  };
  const claims = $derived(Object.entries(m.claims ?? {}));
</script>

<span class="matcher mono">
  <span class="iss">{m.issuer}</span>
  {#each claims as [k, vs] (k)}
    <span class="claim"><span class="k">{k}</span><span class="eq">=</span>{#each vs as v, i (v)}{#if i}<span class="or">|</span>{/if}<span class="v">{v}</span>{#if readable(v)}<span class="readable">{readable(v)}</span>{/if}{/each}</span>
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
  .readable {
    margin-left: 6px;
    font-family: var(--font-ui);
    color: var(--ink-3);
  }
</style>
