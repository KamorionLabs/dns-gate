<script lang="ts">
  import type { Status } from '../lib/types';
  import { statusHelp, statusLabel } from '../lib/labels';
  import Seal from './Seal.svelte';
  let { status }: { status: Status } = $props();
</script>

<span class="badge {status}" title={statusHelp[status]}>
  <Seal {status} size={13} />
  {statusLabel[status]}
</span>

<style>
  .badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    height: 22px;
    padding: 0 8px 0 6px;
    border-radius: 11px;
    font-size: 12px;
    font-weight: 500;
    white-space: nowrap;
  }
  .managed {
    background: var(--seal-ink-wash);
    color: var(--seal-ink);
  }
  .pending {
    background: var(--brass-wash);
    color: var(--brass);
  }
  .tainted,
  .missing {
    background: var(--wax-wash);
    color: var(--wax);
  }
  .foreign {
    background: transparent;
    color: var(--ink-3);
    box-shadow: inset 0 0 0 1px var(--rule);
  }
</style>
