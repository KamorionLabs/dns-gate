<script lang="ts">
  import type { Rule } from '../../lib/types';
  let { rule }: { rule: Rule } = $props();
</script>

<div class="rule">
  {#if rule.zones?.length || !rule.folders?.length}<span class="part"><span class="lbl">zones</span>{#each rule.zones ?? [] as z (z)}<span class="v mono">{z}</span>{/each}</span>{/if}
  {#if rule.folders?.length}<span class="part"><span class="lbl">folders</span>{#each rule.folders as f (f)}<span class="v mono">{f}</span>{/each}</span>{/if}
  <span class="part"><span class="lbl">may</span>{#each rule.actions as a (a)}<span class="v act mono" class:write={a.endsWith('write')} class:meta={a.startsWith('policy.')}>{a}</span>{/each}</span>
  {#if rule.records?.hosts?.length || rule.records?.types?.length}
    <span class="part">
      <span class="lbl">on</span>
      {#each rule.records?.hosts ?? ['any host'] as h (h)}<span class="v mono">{h}</span>{/each}
      <span class="sep">·</span>
      {#each rule.records?.types ?? ['any type'] as t (t)}<span class="v mono t">{t}</span>{/each}
    </span>
  {:else}
    <span class="part"><span class="lbl">on</span><span class="any">every record</span></span>
  {/if}
</div>

<style>
  .rule {
    display: flex;
    flex-wrap: wrap;
    gap: 4px var(--s4);
    padding: 6px var(--s3);
    border-radius: var(--r-sm);
    background: var(--well);
  }
  .part {
    display: inline-flex;
    flex-wrap: wrap;
    align-items: baseline;
    gap: 4px;
  }
  .lbl {
    color: var(--ink-4);
    font-size: 12px;
  }
  .v {
    font-size: 12px;
    color: var(--ink);
  }
  .act {
    padding: 0 5px;
    border-radius: 3px;
    background: var(--rule-soft);
  }
  .write {
    color: var(--seal-ink);
    background: var(--seal-ink-wash);
  }
  .meta {
    color: var(--brass);
    background: var(--brass-wash);
  }
  .t {
    color: var(--ink-2);
  }
  .sep {
    color: var(--ink-4);
  }
  .any {
    color: var(--brass);
    font-size: 12px;
  }
</style>
