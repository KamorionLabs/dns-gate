<script lang="ts">
  import { downloadText } from '../lib/adoptDraft';
  import Icon from './Icon.svelte';

  let { hcl, filename }: { hcl: string; filename: string } = $props();
  let copied = $state(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(hcl);
      copied = true;
      setTimeout(() => (copied = false), 1400);
    } catch {
      copied = false;
    }
  }
</script>

<div class="hcl">
  <div class="bar">
    <span class="mono name">{filename}</span>
    <button class="btn quiet" type="button" onclick={copy}><Icon name={copied ? 'check' : 'copy'} size={13} />{copied ? 'Copied' : 'Copy'}</button>
    <button class="btn quiet" type="button" onclick={() => downloadText(filename, hcl)}><Icon name="download" size={13} />Download</button>
  </div>
  <pre class="mono">{hcl}</pre>
</div>

<style>
  .hcl {
    border-radius: var(--r-md);
    border: 1px solid var(--rule);
    background: var(--well);
    overflow: hidden;
  }
  .bar {
    display: flex;
    align-items: center;
    gap: var(--s1);
    padding: 4px 4px 4px var(--s3);
    border-bottom: 1px solid var(--rule-soft);
    background: var(--sheet);
  }
  .name {
    margin-right: auto;
    font-size: 12px;
    color: var(--ink-3);
  }
  .bar .btn {
    height: 28px;
  }
  pre {
    margin: 0;
    padding: var(--s3) var(--s4);
    max-height: 340px;
    overflow: auto;
    font-size: 12px;
    line-height: 1.6;
    color: var(--ink-2);
  }
</style>
