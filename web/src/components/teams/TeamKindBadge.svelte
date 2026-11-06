<script lang="ts">
  import type { TeamKind } from '../../lib/types';
  import { teamKindHelp, teamKindLabel } from '../../lib/teams';
  let { kind }: { kind: TeamKind } = $props();
</script>

<span class="kind {kind}" title={teamKindHelp[kind]}>{teamKindLabel[kind]}</span>

<style>
  .kind {
    display: inline-flex;
    align-items: center;
    height: 20px;
    padding: 0 7px;
    border-radius: 5px;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.01em;
    white-space: nowrap;
    background: var(--seal-ink-wash);
    color: var(--seal-ink);
  }
  .kind.auto,
  .kind.family,
  .kind.claim {
    background: var(--pencil-wash);
    color: var(--ink-2);
  }
  .kind.store {
    background: var(--brass-wash);
    color: var(--brass);
  }
</style>
