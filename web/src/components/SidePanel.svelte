<script lang="ts">
  import type { Snippet } from 'svelte';
  import Icon from './Icon.svelte';

  // Modal side panel (native <dialog>) shared by record, adoption and export panels.
  let { title, onclose, width = 560, head, children }: { title: string; onclose: () => void; width?: number; head?: Snippet; children: Snippet } = $props();
  let dialog: HTMLDialogElement;
  let panel: HTMLDivElement;

  $effect(() => {
    dialog.showModal();
    panel.focus();
    return () => dialog.close();
  });
</script>

<dialog bind:this={dialog} class="side" style:--w="{width}px" aria-label={title} onclose={onclose} onclick={(e) => e.target === dialog && onclose()}>
  <div class="panel" bind:this={panel} tabindex="-1">
    <header>
      <div class="t">{#if head}{@render head()}{:else}<h2>{title}</h2>{/if}</div>
      <button class="btn quiet icon" type="button" aria-label="Close" onclick={onclose}><Icon name="x" /></button>
    </header>
    <div class="scroll">{@render children()}</div>
  </div>
</dialog>

<style>
  .side {
    margin: 0 0 0 auto;
    padding: 0;
    border: 0;
    width: min(var(--w), 100vw);
    max-width: 100vw;
    height: 100dvh;
    max-height: 100dvh;
    background: transparent;
    color: var(--ink);
  }
  .side::backdrop {
    background: var(--scrim);
    animation: fade 200ms var(--ease-out);
  }
  .panel {
    outline: none;
    height: 100%;
    display: grid;
    grid-template-rows: auto minmax(0, 1fr);
    background: var(--sheet-raised);
    border-left: 1px solid var(--rule);
    animation: slide 260ms var(--ease-out);
  }
  @keyframes slide {
    from {
      transform: translateX(24px);
      opacity: 0;
    }
  }
  @keyframes fade {
    from {
      opacity: 0;
    }
  }
  header {
    display: flex;
    align-items: flex-start;
    gap: var(--s3);
    padding: var(--s5) var(--s5) var(--s4);
    border-bottom: 1px solid var(--rule-soft);
  }
  .t {
    flex: 1;
    min-width: 0;
  }
  h2 {
    font-size: var(--t-lead);
  }
  header .btn {
    margin: -4px -8px 0 0;
  }
  .scroll {
    overflow-y: auto;
    padding: var(--s4) var(--s5) var(--s8);
    display: grid;
    align-content: start;
    gap: var(--s5);
  }
</style>
