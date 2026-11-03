<script lang="ts">
  import { untrack } from 'svelte';
  import { api } from '../lib/api';
  import SidePanel from './SidePanel.svelte';
  import HclBlock from './HclBlock.svelte';
  import Icon from './Icon.svelte';

  let { zone, teams, owners, onclose }: { zone: string; teams: string[]; owners: string[]; onclose: () => void } = $props();

  const choices = $derived([...new Set([...teams, ...owners])]);
  let team = $state(untrack(() => teams[0] ?? ''));
  let hcl = $state<string | null>(null);
  let error = $state<string | null>(null);

  $effect(() => {
    const t = team;
    hcl = null;
    error = null;
    api
      .terraform(zone, { team: t || undefined })
      .then((h) => (hcl = h))
      .catch((e: Error) => (error = e.message));
  });
</script>

<SidePanel title="Export Terraform" {onclose} width={640}>
  {#snippet head()}
    <p class="eyebrow">Export Terraform</p>
    <h2 class="mono">{zone}</h2>
  {/snippet}
  <p class="dim">Record sets managed by the gate, as <span class="mono">eurodns_record_set</span> resources with import blocks. Paste into your stack, the first plan should be empty.</p>
  <label class="team">
    <span class="lbl">Team</span>
    <span class="field"><select bind:value={team}>
      <option value="">All teams</option>
      {#each choices as t (t)}<option value={t}>{t}</option>{/each}
    </select><span class="chev"><Icon name="chevron" size={12} /></span></span>
  </label>
  {#if error}<p class="fail">{error}</p>
  {:else if hcl}<HclBlock {hcl} filename="{zone.replaceAll('.', '_')}{team ? '_' + team : ''}.tf" />
  {:else}<div class="skeleton line"></div>{/if}
</SidePanel>

<style>
  h2 {
    font-size: var(--t-h3);
  }
  .dim {
    color: var(--ink-3);
  }
  .team {
    display: grid;
    gap: 4px;
  }
  .team .field {
    justify-self: start;
  }
  .lbl {
    font-size: 12px;
    font-weight: 500;
    color: var(--ink-2);
  }
  .fail {
    color: var(--wax);
  }
  .line {
    height: 120px;
  }
</style>
