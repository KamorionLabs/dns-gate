<script lang="ts">
  import type { RevisionStatus } from '../../lib/types';
  let { status, stale = false }: { status: RevisionStatus; stale?: boolean } = $props();
  const label: Record<RevisionStatus, string> = {
    proposed: 'Awaiting review',
    approved: 'Approved',
    rejected: 'Rejected',
    active: 'Active',
    superseded: 'Superseded',
  };
</script>

<span class="badges">
  <span class="b {status}">{label[status]}</span>
  {#if stale}<span class="b stale" title="Based on a revision that is no longer active: review the diff against the current policy">Stale</span>{/if}
</span>

<style>
  .badges {
    display: inline-flex;
    gap: 4px;
  }
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
  .proposed {
    color: var(--brass);
    background: var(--brass-wash);
  }
  .approved {
    color: var(--stamp);
    background: var(--stamp-wash);
  }
  .active {
    color: var(--sheet);
    background: var(--seal-ink);
  }
  .rejected {
    color: var(--wax);
    background: var(--wax-wash);
  }
  .superseded {
    color: var(--ink-3);
    box-shadow: inset 0 0 0 1px var(--rule);
  }
  .stale {
    color: var(--wax);
    box-shadow: inset 0 0 0 1px color-mix(in srgb, var(--wax) 45%, transparent);
  }
</style>
