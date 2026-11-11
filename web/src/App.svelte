<script lang="ts">
  import { api, ApiError } from './lib/api';
  import type { Me } from './lib/types';
  import { router } from './lib/router.svelte';
  import Header from './components/Header.svelte';
  import Footer from './components/Footer.svelte';
  import ZonesView from './views/ZonesView.svelte';
  import ZoneView from './views/ZoneView.svelte';
  import JournalView from './views/JournalView.svelte';
  import ConnectView from './views/ConnectView.svelte';
  import PolicyOverview from './views/PolicyOverview.svelte';
  import PolicyEdit from './views/PolicyEdit.svelte';
  import ProposalsView from './views/ProposalsView.svelte';
  import ProposalView from './views/ProposalView.svelte';
  import SimulatorView from './views/SimulatorView.svelte';
  import TeamsView from './views/TeamsView.svelte';
  import TeamView from './views/TeamView.svelte';
  import TransfersView from './views/TransfersView.svelte';
  import TransferView from './views/TransferView.svelte';

  // Nothing of the console is drawn before the gate has confirmed who is
  // signed in: without a session the 401 sends the browser to the sign-in
  // page, and the header, navigation and views (with their own API calls)
  // must not show meanwhile.
  let me = $state<Me | null>(null);
  let failure = $state<string | null>(null);

  function identify() {
    failure = null;
    api
      .me()
      .then((m) => (me = m))
      .catch((e: Error) => {
        // 401: the request layer is already redirecting to sign-in.
        if (!(e instanceof ApiError && e.status === 401)) failure = e.message || 'The gate did not answer';
      });
  }
  $effect(identify);
</script>

{#if !me}
  <div class="gate" aria-live="polite">
    {#if failure}
      <div class="empty">
        <strong>The console could not identify you</strong>
        {failure}
        <p><button class="btn" type="button" onclick={identify}>Try again</button></p>
      </div>
    {:else}
      <p class="signing">Signing in…</p>
    {/if}
  </div>
{:else}
<Header {me} />

<main>
  {#if router.route.name === 'zone'}
    {#key router.route.zone}<ZoneView zone={router.route.zone} />{/key}
  {:else if router.route.name === 'journal'}
    <JournalView />
  {:else if router.route.name === 'connect'}
    <ConnectView />
  {:else if router.route.name === 'teams'}
    <TeamsView />
  {:else if router.route.name === 'team'}
    {#key router.route.team}<TeamView team={router.route.team} />{/key}
  {:else if router.route.name === 'transfers'}
    <TransfersView />
  {:else if router.route.name === 'transfer'}
    {#key router.route.id}<TransferView id={router.route.id} />{/key}
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

<Footer />
{/if}

<style>
  .gate {
    flex: 1;
    display: grid;
    place-items: center;
    padding: var(--s8) var(--s6);
  }
  /* Shown only when identifying takes a while (a cold start, a slow
     identity provider); a quick redirect to sign-in leaves the page blank. */
  .signing {
    color: var(--ink-3);
    opacity: 0;
    animation: appear 0.2s ease-out 0.8s forwards;
  }
  @keyframes appear {
    to {
      opacity: 1;
    }
  }
  @media (prefers-reduced-motion: reduce) {
    .signing {
      animation-duration: 0s;
    }
  }
  :global(#app) {
    min-height: 100vh;
    display: flex;
    flex-direction: column;
  }
  main {
    flex: 1;
    width: 100%;
    max-width: var(--page-max);
    margin: 0 auto;
    padding: var(--s8) var(--s6) var(--s10);
  }
  @media (max-width: 720px) {
    main {
      padding: var(--s5) var(--s4) var(--s8);
    }
  }
</style>
