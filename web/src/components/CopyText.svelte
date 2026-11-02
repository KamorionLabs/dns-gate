<script lang="ts">
  import Icon from './Icon.svelte';
  let { text, label }: { text: string; label?: string } = $props();
  let copied = $state(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      copied = true;
      setTimeout(() => (copied = false), 1400);
    } catch {
      copied = false;
    }
  }
</script>

<button type="button" class="copy mono" onclick={copy} title="Copy {label ?? text}">
  <span class="text">{text}</span>
  <span class="ico" class:ok={copied}><Icon name={copied ? 'check' : 'copy'} size={12} /></span>
  <span class="sr-only" aria-live="polite">{copied ? 'Copied' : ''}</span>
</button>

<style>
  .copy {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 2px 6px;
    margin: -2px -6px;
    border: 0;
    border-radius: var(--r-sm);
    background: transparent;
    color: var(--ink-3);
    cursor: pointer;
    font-size: 11.5px;
  }
  .copy:hover {
    background: var(--rule-soft);
    color: var(--ink-2);
  }
  .ico {
    opacity: 0;
    transition: opacity 120ms var(--ease-out);
  }
  .copy:hover .ico,
  .copy:focus-visible .ico,
  .ico.ok {
    opacity: 1;
  }
  .ok {
    color: var(--stamp);
  }
</style>
