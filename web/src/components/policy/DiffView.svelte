<script lang="ts">
  let { diff }: { diff: string } = $props();
  const lines = $derived(
    diff.split('\n').map((l) => ({
      kind: l.startsWith('+++') || l.startsWith('---') ? 'file' : l.startsWith('@@') ? 'hunk' : l[0] === '+' ? 'add' : l[0] === '-' ? 'del' : 'ctx',
      text: l,
    })),
  );
</script>

<pre class="diff mono" aria-label="YAML diff">{#each lines as l, i (i)}<span class="ln {l.kind}">{l.kind === 'hunk' ? '⋯' : l.text}</span>
{/each}</pre>

<style>
  .diff {
    margin: 0;
    padding: var(--s2) 0;
    border-radius: var(--r-md);
    background: var(--well);
    border: 1px solid var(--rule-soft);
    overflow-x: auto;
    font-size: 12px;
    line-height: 1.6;
  }
  .ln {
    display: inline-block;
    min-width: 100%;
    padding: 0 var(--s4);
    white-space: pre;
    color: var(--ink-2);
  }
  .file {
    color: var(--ink-4);
  }
  .hunk {
    color: var(--ink-4);
    background: var(--rule-soft);
  }
  .add {
    background: var(--stamp-wash);
    color: var(--ink);
    box-shadow: inset 3px 0 0 var(--stamp);
  }
  .del {
    background: var(--wax-wash);
    color: var(--ink-2);
    box-shadow: inset 3px 0 0 var(--wax);
  }
</style>
