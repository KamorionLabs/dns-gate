<script lang="ts">
  import type { EMatcher } from '../../lib/editor';
  import type { ValidationError } from '../../lib/types';
  import ChipsInput from '../ChipsInput.svelte';
  import FieldError from '../FieldError.svelte';
  import Icon from '../Icon.svelte';

  let {
    matchers = $bindable([]),
    issuers,
    path,
    errors,
    noun = 'member',
  }: { matchers: EMatcher[]; issuers: string[]; path: string; errors: ValidationError[]; noun?: string } = $props();

  const add = () => (matchers = [...matchers, { issuer: issuers[0] ?? '', claims: [{ key: 'sub', values: [] }] }]);
</script>

<div class="matchers">
  {#each matchers as m, i (i)}
    <div class="m">
      <div class="row">
        <label class="field iss">
          <span class="sr-only">Issuer</span>
          <select bind:value={m.issuer}>
            {#each issuers as is (is)}<option value={is}>{is}</option>{/each}
            {#if m.issuer && !issuers.includes(m.issuer)}<option value={m.issuer}>{m.issuer}</option>{/if}
          </select>
          <span class="chev"><Icon name="chevron" size={12} /></span>
        </label>
        <button type="button" class="btn quiet icon" aria-label="Remove {noun}" onclick={() => (matchers = matchers.filter((_, k) => k !== i))}><Icon name="trash" size={14} /></button>
      </div>
      <FieldError {errors} path="{path}[{i}].issuer" />
      {#each m.claims as c, j (j)}
        <div class="claim">
          <input class="key mono" aria-label="Claim name" placeholder="claim" bind:value={c.key} />
          <span class="eq">matches</span>
          <ChipsInput bind:values={c.values} label="Values for {c.key}" placeholder="value or glob, Enter to add" />
          <button type="button" class="btn quiet icon" aria-label="Remove claim" onclick={() => (m.claims = m.claims.filter((_, k) => k !== j))}><Icon name="x" size={12} /></button>
        </div>
      {/each}
      <button type="button" class="link" onclick={() => (m.claims = [...m.claims, { key: '', values: [] }])}><Icon name="plus" size={12} /> claim</button>
    </div>
  {/each}
  <FieldError {errors} path={path} />
  <button type="button" class="link" onclick={add}><Icon name="plus" size={12} /> {noun}</button>
</div>

<style>
  .matchers {
    display: grid;
    gap: var(--s2);
  }
  .m {
    display: grid;
    gap: 6px;
    padding: var(--s2) var(--s3);
    border-radius: var(--r-md);
    background: var(--well);
  }
  .row {
    display: flex;
    justify-content: space-between;
    gap: var(--s2);
  }
  .iss {
    background: var(--sheet-raised);
  }
  .claim {
    display: grid;
    grid-template-columns: 140px auto minmax(0, 1fr) auto;
    gap: var(--s2);
    align-items: center;
  }
  .claim :global(.chips) {
    background: var(--sheet-raised);
  }
  .key {
    height: 32px;
    padding: 0 var(--s2);
    border: 1px solid var(--rule);
    border-radius: var(--r-md);
    background: var(--sheet-raised);
    font-size: 12px;
    min-width: 0;
  }
  .eq {
    color: var(--ink-4);
    font-size: 12px;
  }
  .link {
    justify-self: start;
    display: inline-flex;
    align-items: center;
    gap: 4px;
    border: 0;
    background: none;
    padding: 2px 0;
    color: var(--seal-ink);
    cursor: pointer;
    font-size: 13px;
    font-weight: 500;
  }
  .link:hover {
    text-decoration: underline;
  }
  @media (max-width: 640px) {
    .claim {
      grid-template-columns: minmax(0, 1fr) auto;
    }
    .eq {
      display: none;
    }
    .claim :global(.chips) {
      grid-column: 1 / -1;
    }
  }
</style>
