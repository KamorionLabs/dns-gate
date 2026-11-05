<script lang="ts">
  import { providerLabel } from '../lib/labels';

  // The DNS provider hosting a zone (EuroDNS, Route53).
  let { provider }: { provider?: string } = $props();
</script>

{#if provider}<span class="provider {provider.toLowerCase()}" title="Hosted at {providerLabel(provider)}">{providerLabel(provider)}</span>{/if}

<style>
  .provider {
    display: inline-flex;
    align-items: center;
    flex: none;
    height: 18px;
    padding: 0 6px;
    border: 1px solid var(--rule);
    border-radius: 5px;
    color: var(--ink-3);
    font-family: var(--font-ui);
    font-size: 11px;
    font-weight: 500;
    letter-spacing: 0.01em;
    white-space: nowrap;
    vertical-align: 2px;
    margin-left: 4px;
  }
</style>
