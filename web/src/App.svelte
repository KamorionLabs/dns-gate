<script lang="ts">
  import { api } from './lib/api';
  import type { Me } from './lib/types';
  import { router } from './lib/router.svelte';
  import Header from './components/Header.svelte';
  import ZonesView from './views/ZonesView.svelte';
  import ZoneView from './views/ZoneView.svelte';
  import JournalView from './views/JournalView.svelte';
  import PolicyOverview from './views/PolicyOverview.svelte';
  import PolicyEdit from './views/PolicyEdit.svelte';
  import ProposalsView from './views/ProposalsView.svelte';
  import ProposalView from './views/ProposalView.svelte';
  import SimulatorView from './views/SimulatorView.svelte';

  let me = $state<Me | null>(null);
  $effect(() => {
    api.me().then((m) => (me = m)).catch(() => (me = null));
  });
</script>

<Header {me} />

<main>
  {#if router.route.name === 'zone'}
    {#key router.route.zone}<ZoneView zone={router.route.zone} />{/key}
  {:else if router.route.name === 'journal'}
    <JournalView />
  {:else if router.route.name === 'proposal'}
    {#key router.route.id}<ProposalView id={router.route.id} />{/key}
  {:else if router.route.name === 'policy'}
    {#if router.route.tab === 'edit'}<PolicyEdit />
    {:else if router.route.tab === 'proposals'}<ProposalsView />
    {:else if router.route.tab === 'simulate'}<SimulatorView />
    {:else}<PolicyOverview />{/if}
  {:else}
    <ZonesView />
  {/if}
</main>

<style>
  main {
    max-width: 1320px;
    margin: 0 auto;
    padding: var(--s8) var(--s6) var(--s10);
  }
  @media (max-width: 720px) {
    main {
      padding: var(--s5) var(--s4) var(--s8);
    }
  }
</style>
