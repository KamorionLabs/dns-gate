<script lang="ts">
  import type { ZoneAccess } from '../../lib/access';
  import { teamFromText, teamLabel } from '../../lib/team';
  import LayerTag from './LayerTag.svelte';
  import Matcher from './Matcher.svelte';

  // Who can do what in one zone: every binding with a rule there, its team,
  // who it is granted to and what it allows, in plain sentences.
  let { access, showZone = true }: { access: ZoneAccess; showZone?: boolean } = $props();
</script>

<div class="zone-access">
  {#if showZone}<h3 class="mono">{access.zone}</h3>{/if}
  {#if access.entries.length === 0}
    <p class="dim">No binding grants anything in this zone.</p>
  {:else}
    <ul>
      {#each access.entries as { lb, allows }, i (i)}
        <li>
          <div class="who">
            <span class="team" title={lb.binding.team_from ? teamFromText(lb.binding.team_from) : undefined}>{teamLabel(lb.binding.team, lb.binding.team_from)}</span>
            <span class="dim">through</span>
            <span class="role mono">{lb.binding.role}</span>
            <LayerTag layer={lb.layer} rev={lb.rev} />
          </div>
          <div class="members">
            <span class="dim">Granted to</span>
            {#each lb.binding.groups ?? [] as g (g)}<span class="grp mono">{g}</span>{/each}
            {#each lb.binding.subjects ?? [] as m, k (k)}<Matcher {m} />{/each}
          </div>
          <ul class="allows">
            {#each allows as a (a)}<li>{a}</li>{/each}
          </ul>
        </li>
      {/each}
    </ul>
  {/if}
</div>

<style>
  .zone-access {
    display: grid;
    gap: var(--s2);
    min-width: 0;
  }
  h3 {
    font-size: 13px;
    font-weight: 600;
  }
  ul {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: var(--s2);
  }
  ul > li {
    display: grid;
    gap: 4px;
    padding: var(--s2) var(--s3);
    border-radius: var(--r-md);
    border: 1px solid var(--rule-soft);
    background: var(--sheet);
    min-width: 0;
  }
  .who,
  .members {
    display: flex;
    flex-wrap: wrap;
    align-items: baseline;
    gap: 4px 6px;
    min-width: 0;
  }
  .team {
    font-weight: 600;
    color: var(--seal-ink);
  }
  .role {
    font-weight: 600;
    font-size: 12px;
  }
  .grp {
    font-size: 11.5px;
    padding: 0 6px;
    border-radius: 10px;
    box-shadow: inset 0 0 0 1px var(--rule-strong);
  }
  .dim {
    color: var(--ink-3);
    font-size: 12px;
  }
  ul.allows {
    gap: 0;
    padding-left: var(--s4);
    list-style: disc;
    color: var(--ink-2);
  }
  ul.allows > li {
    display: list-item;
    padding: 0;
    border: 0;
    background: none;
  }
</style>
