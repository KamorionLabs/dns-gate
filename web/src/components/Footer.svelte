<script lang="ts">
  import { api } from '../lib/api';

  const REPO = 'https://github.com/KamorionLabs/eurodns-gate';

  let version = $state('');
  $effect(() => {
    api
      .gateInfo()
      .then((g) => (version = g.version))
      .catch(() => (version = ''));
  });
</script>

<footer class="foot">
  <div class="inner">
    <span class="project">
      <a href={REPO} target="_blank" rel="noopener">github.com/KamorionLabs/eurodns-gate</a>
      {#if version}<span class="version mono" title="Gate version">{version}</span>{/if}
    </span>
    <span class="made">Made with <span role="img" aria-label="love">❤️</span> by <a href="https://kamorion.com" target="_blank" rel="noopener">Kamorion</a></span>
  </div>
</footer>

<style>
  .foot {
    border-top: 1px solid var(--rule-soft);
    color: var(--ink-3);
    font-size: var(--t-caption);
  }
  .inner {
    max-width: var(--page-max);
    margin: 0 auto;
    padding: var(--s4) var(--s6);
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: var(--s2) var(--s6);
  }
  .project {
    display: inline-flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--s2);
    min-width: 0;
  }
  .version {
    font-size: var(--t-caption);
    padding: 0 6px;
    border-radius: 8px;
    background: var(--well);
    color: var(--ink-3);
  }
  a {
    color: var(--ink-2);
    text-decoration: none;
    overflow-wrap: anywhere;
  }
  a:hover {
    color: var(--ink);
    text-decoration: underline;
    text-underline-offset: 2px;
  }
  @media (max-width: 720px) {
    .inner {
      padding: var(--s4);
    }
  }
  @media (max-width: 480px) {
    .inner {
      flex-direction: column;
      align-items: flex-start;
    }
  }
</style>
