<script lang="ts">
  import { clock } from '../lib/clock.svelte';
  import { absolute, relative } from '../lib/format';
  let { iso, prefix = '' }: { iso: string | undefined; prefix?: string } = $props();
</script>

{#if iso}<time datetime={iso} title={absolute(iso)} class="num">{prefix}{relative(iso, clock.now)}</time>{:else}<span class="none">—</span>{/if}

<style>
  time {
    white-space: nowrap;
  }
  .none {
    color: var(--ink-4);
  }
</style>
