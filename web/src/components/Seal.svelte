<script lang="ts">
  import type { Status } from '../lib/types';

  // The custody seal: intact when the gate holds the record, broken when it
  // drifted, dotted when the gate has no claim on it.
  let { status, size = 14, title }: { status: Status; size?: number; title?: string } = $props();
</script>

<svg
  class="seal {status}"
  width={size}
  height={size}
  viewBox="0 0 16 16"
  role={title ? 'img' : 'presentation'}
  aria-hidden={title ? undefined : 'true'}
  aria-label={title}
>
  {#if status === 'managed'}
    <circle cx="8" cy="8" r="6" fill="none" stroke="currentColor" stroke-width="1.6" />
    <circle cx="8" cy="8" r="2.5" fill="currentColor" />
  {:else if status === 'pending'}
    <circle cx="8" cy="8" r="6" fill="none" stroke="currentColor" stroke-width="1.6" stroke-dasharray="2.4 1.8" />
    <circle cx="8" cy="8" r="2.2" fill="currentColor" opacity="0.55" />
  {:else if status === 'tainted'}
    <path d="M12.6 4.1 A6 6 0 1 1 9.6 2.2" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" />
    <path d="M10.4 1.6 L11.4 3.6 L13.6 3.2" fill="none" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round" />
    <circle cx="8" cy="8" r="2.5" fill="currentColor" />
  {:else if status === 'missing'}
    <circle cx="8" cy="8" r="6" fill="none" stroke="currentColor" stroke-width="1.6" stroke-dasharray="2.4 1.8" />
    <path d="M5.2 10.8 L10.8 5.2" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" />
  {:else}
    <circle cx="8" cy="8" r="6" fill="none" stroke="currentColor" stroke-width="1.6" stroke-dasharray="0.01 2.65" stroke-linecap="round" />
  {/if}
</svg>

<style>
  .seal {
    flex: none;
    display: block;
  }
  .managed {
    color: var(--seal-ink);
  }
  .pending {
    color: var(--brass);
  }
  .tainted,
  .missing {
    color: var(--wax);
  }
  .foreign {
    color: var(--pencil);
  }
</style>
