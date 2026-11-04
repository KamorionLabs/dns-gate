<script lang="ts">
  let {
    options,
    values = $bindable([]),
    label,
    mono = true,
    invalid = false,
    danger = [],
  }: { options: string[]; values: string[]; label: string; mono?: boolean; invalid?: boolean; danger?: string[] } = $props();
  const toggle = (o: string) => (values = values.includes(o) ? values.filter((v) => v !== o) : [...values, o]);
  const opts = $derived([...new Set(options)]);
  const extra = $derived(values.filter((v) => !opts.includes(v)));
</script>

<div class="toggles" class:invalid role="group" aria-label={label}>
  {#each opts as o (o)}
    <button type="button" class="t" class:mono class:danger={danger.includes(o)} aria-pressed={values.includes(o)} onclick={() => toggle(o)}>{o}</button>
  {/each}
  {#each extra as o (o)}
    <button type="button" class="t unknown" class:mono aria-pressed="true" title="Not an available option" onclick={() => toggle(o)}>{o}</button>
  {/each}
  {#if !opts.length && !extra.length}<span class="none">nothing to choose from yet</span>{/if}
</div>

<style>
  .toggles {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
  }
  .invalid .t[aria-pressed='true'] {
    box-shadow: 0 0 0 1px var(--wax);
  }
  .t {
    height: 26px;
    padding: 0 9px;
    border-radius: 13px;
    border: 0;
    background: transparent;
    box-shadow: inset 0 0 0 1px var(--rule);
    color: var(--ink-3);
    cursor: pointer;
    font-size: 12px;
    transition:
      background-color 100ms var(--ease-out),
      color 100ms var(--ease-out);
  }
  .t.mono {
    font-family: var(--font-record);
    font-size: 12px;
  }
  .t:hover {
    color: var(--ink);
    box-shadow: inset 0 0 0 1px var(--rule-strong);
  }
  .t[aria-pressed='true'] {
    background: var(--seal-ink-wash);
    color: var(--seal-ink);
    box-shadow: inset 0 0 0 1px color-mix(in srgb, var(--seal-ink) 35%, transparent);
  }
  .t.danger[aria-pressed='true'] {
    background: var(--brass-wash);
    color: var(--brass);
  }
  .t.unknown {
    background: var(--wax-wash);
    color: var(--wax);
    box-shadow: none;
    text-decoration: line-through;
  }
  .none {
    color: var(--ink-4);
    font-size: 12px;
  }
</style>
