<script lang="ts">
  import type { Actor } from '../lib/types';
  import { categoryLabel } from '../lib/labels';
  import { identityLabel } from '../lib/identity';
  import Icon from './Icon.svelte';

  // The one way an identity is shown: readable label, kind icon, full subject on hover.
  let { actor, quiet = false }: { actor: Actor; quiet?: boolean } = $props();
  const id = $derived(identityLabel(actor));
  const system = $derived(id.kind === 'system');
  const icon = $derived(system ? 'gate' : (id.kind as 'human' | 'pipeline' | 'key'));
  const kind = $derived(system ? 'Gate' : categoryLabel[id.kind]);
</script>

<span class="actor {system ? 'system' : id.kind}" class:quiet title="{kind} · {id.full}">
  <span class="glyph"><Icon name={icon} size={12} /></span>
  <span class="name">{id.label}</span>
  <span class="sr-only">({kind})</span>
</span>

<style>
  .actor {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    max-width: 100%;
    min-width: 0;
    color: var(--ink);
    font-weight: 500;
  }
  .quiet {
    color: var(--ink-2);
    font-weight: 400;
  }
  .glyph {
    display: grid;
    place-items: center;
    width: 20px;
    height: 20px;
    flex: none;
    border-radius: 50%;
    background: var(--rule-soft);
    color: var(--ink-2);
  }
  .pipeline .glyph {
    background: var(--seal-ink-wash);
    color: var(--seal-ink);
  }
  .key .glyph {
    background: var(--brass-wash);
    color: var(--brass);
  }
  .system .glyph {
    background: transparent;
    color: var(--ink-3);
    box-shadow: inset 0 0 0 1px var(--rule);
  }
  .name {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
</style>
