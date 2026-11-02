<script lang="ts">
  import Icon from './Icon.svelte';
  let {
    values = $bindable([]),
    placeholder = '',
    label,
    mono = true,
    invalid = false,
    id,
  }: { values: string[]; placeholder?: string; label: string; mono?: boolean; invalid?: boolean; id?: string } = $props();
  let text = $state('');

  function commit() {
    const parts = text.split(/[,\s]+/).map((s) => s.trim()).filter(Boolean);
    if (parts.length) values = [...values, ...parts.filter((p) => !values.includes(p))];
    text = '';
  }
  function onkey(e: KeyboardEvent) {
    if (e.key === 'Enter' || e.key === ',') {
      e.preventDefault();
      commit();
    } else if (e.key === 'Backspace' && !text && values.length) {
      values = values.slice(0, -1);
    }
  }
</script>

<div class="chips" class:mono class:invalid>
  {#each values as v, i (v)}
    <span class="chip">{v}<button type="button" aria-label="Remove {v}" onclick={() => (values = values.filter((_, k) => k !== i))}><Icon name="x" size={10} /></button></span>
  {/each}
  <input {id} aria-label={label} placeholder={values.length ? '' : placeholder} bind:value={text} onkeydown={onkey} onblur={commit} />
</div>

<style>
  .chips {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 4px;
    min-height: 32px;
    padding: 3px 6px;
    background: var(--well);
    border: 1px solid var(--rule);
    border-radius: var(--r-md);
    cursor: text;
  }
  .chips:focus-within {
    border-color: var(--rule-strong);
    outline: 2px solid var(--focus);
    outline-offset: 1px;
  }
  .invalid {
    border-color: color-mix(in srgb, var(--wax) 60%, transparent);
  }
  .chip {
    display: inline-flex;
    align-items: center;
    gap: 2px;
    height: 22px;
    padding: 0 2px 0 7px;
    border-radius: 4px;
    background: var(--sheet-raised);
    box-shadow: 0 0 0 1px var(--rule);
    font-size: 12px;
  }
  .mono .chip,
  .mono input {
    font-family: var(--font-record);
    font-size: 12px;
  }
  .chip button {
    display: grid;
    place-items: center;
    width: 18px;
    height: 18px;
    border: 0;
    border-radius: 3px;
    background: transparent;
    color: var(--ink-3);
    cursor: pointer;
  }
  .chip button:hover {
    background: var(--wax-wash);
    color: var(--wax);
  }
  input {
    flex: 1;
    min-width: 80px;
    height: 24px;
    border: 0;
    background: transparent;
    outline: none;
  }
</style>
