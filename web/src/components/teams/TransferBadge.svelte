<script lang="ts">
  import type { TransferStatus } from '../../lib/types';
  import { transferStatusLabel } from '../../lib/teams';
  let { status }: { status: TransferStatus } = $props();
</script>

<span class="b {status}">{transferStatusLabel[status]}</span>

<style>
  .b {
    display: inline-flex;
    align-items: center;
    height: 20px;
    padding: 0 8px;
    border-radius: 6px;
    font-size: 12px;
    font-weight: 600;
    white-space: nowrap;
  }
  .proposed,
  .applying {
    color: var(--brass);
    background: var(--brass-wash);
  }
  .applied {
    color: var(--stamp);
    background: var(--stamp-wash);
  }
  .rejected,
  .failed {
    color: var(--wax);
    background: var(--wax-wash);
  }
  .expired {
    color: var(--ink-3);
    box-shadow: inset 0 0 0 1px var(--rule);
  }
</style>
