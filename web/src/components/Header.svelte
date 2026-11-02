<script lang="ts">
  import type { Me } from '../lib/types';
  import { router, href, connectHref } from '../lib/router.svelte';
  import { applyTheme, initialTheme, type Theme } from '../lib/theme';
  import { categoryLabel } from '../lib/labels';
  import { usingFixtures } from '../lib/api';
  import { describePermissions } from '../lib/permissions';
  import Icon from './Icon.svelte';
  import Seal from './Seal.svelte';

  let { me }: { me: Me | null } = $props();
  let theme = $state<Theme>(initialTheme());
  let open = $state(false);

  function toggleTheme() {
    theme = theme === 'dark' ? 'light' : 'dark';
    applyTheme(theme, true);
  }

  const section = $derived(
    router.route.name === 'journal' || router.route.name === 'connect'
      ? router.route.name
      : router.route.name === 'policy' || router.route.name === 'proposal'
        ? 'policy'
        : 'zones',
  );
  const can = $derived(describePermissions(me?.permissions ?? []));
  const initials = $derived(
    (me?.name ?? '?')
      .replace(/@.*/, '')
      .split(/[.\-_ ]/)
      .filter(Boolean)
      .slice(0, 2)
      .map((p) => p[0]?.toUpperCase())
      .join(''),
  );

  function closeOnOutside(e: MouseEvent) {
    if (!(e.target as HTMLElement).closest('.who')) open = false;
  }
</script>

<svelte:window onclick={closeOnOutside} onkeydown={(e) => e.key === 'Escape' && (open = false)} />

<header class="bar">
  <div class="inner">
    <a class="mark" href={href('/')}>
      <Seal status="managed" size={18} />
      <span class="word">eurodns<span class="dim">-gate</span></span>
    </a>

    <nav aria-label="Sections">
      <a href={href('/')} aria-current={section === 'zones' ? 'page' : undefined}>Zones</a>
      <a href={href('/journal')} aria-current={section === 'journal' ? 'page' : undefined}>Journal</a>
      <a href={href('/policy')} aria-current={section === 'policy' ? 'page' : undefined}>Policy</a>
      <a href={connectHref()} aria-current={section === 'connect' ? 'page' : undefined}>Connect</a>
    </nav>

    <div class="tools">
      {#if usingFixtures}<span class="demo" title="Fixture data, no backend">Demo data</span>{/if}
      <button class="btn quiet icon" type="button" onclick={toggleTheme} aria-label="Switch to {theme === 'dark' ? 'light' : 'dark'} theme">
        <Icon name={theme === 'dark' ? 'sun' : 'moon'} />
      </button>
      {#if me}
        <div class="who">
          <button class="avatar" type="button" aria-haspopup="true" aria-expanded={open} onclick={() => (open = !open)}>
            <span class="initials">{initials}</span>
            <span class="me-name">{me.name}</span>
            <Icon name="chevron" size={14} />
          </button>
          {#if open}
            <div class="menu" role="menu">
              <div class="menu-head">
                <strong>{me.name}</strong>
                <span class="mono sub">{me.subject}</span>
                <span class="eyebrow">{categoryLabel[me.category]}</span>
              </div>
              <dl>
                <dt class="eyebrow">Teams</dt>
                <dd>{#each me.teams as t (t)}<span class="tag">{t}</span>{:else}<span class="sub">none</span>{/each}</dd>
                {#if me.groups?.length}
                  <dt class="eyebrow">Groups</dt>
                  <dd>{#each me.groups as g (g)}<span class="tag role">{g}</span>{/each}</dd>
                {/if}
                <dt class="eyebrow">Roles</dt>
                <dd>{#each me.roles as r (r)}<span class="tag role">{r}</span>{:else}<span class="sub">none</span>{/each}</dd>
              </dl>
              {#if me.permissions}
                <div class="can">
                  <p class="eyebrow">What you can do</p>
                  <ul>
                    {#each can as c (c)}<li>{c}</li>{:else}<li class="sub">Nothing yet: ask a policy administrator for a role.</li>{/each}
                  </ul>
                </div>
              {/if}
              <a class="item" role="menuitem" href={connectHref()} onclick={() => (open = false)}><Icon name="arrow" size={14} /> Connect your tools</a>
              <a class="item signout" role="menuitem" href="/auth/logout"><Icon name="logout" size={14} /> Sign out</a>
            </div>
          {/if}
        </div>
      {/if}
    </div>
  </div>
</header>

<style>
  .bar {
    position: sticky;
    top: 0;
    z-index: 10;
    background: color-mix(in srgb, var(--paper) 88%, transparent);
    backdrop-filter: saturate(1.4) blur(10px);
    border-bottom: 1px solid var(--rule);
  }
  .inner {
    max-width: 1320px;
    margin: 0 auto;
    height: 52px;
    padding: 0 var(--s6);
    display: flex;
    align-items: center;
    gap: var(--s8);
  }
  .mark {
    display: inline-flex;
    align-items: center;
    gap: var(--s2);
    text-decoration: none;
    color: var(--seal-ink);
  }
  .word {
    font-family: var(--font-record);
    font-weight: 600;
    font-size: 13px;
    color: var(--ink);
    letter-spacing: -0.01em;
  }
  .dim {
    color: var(--ink-3);
    font-weight: 500;
  }
  nav {
    display: flex;
    gap: var(--s1);
    height: 100%;
  }
  nav a {
    display: inline-flex;
    align-items: center;
    padding: 0 var(--s3);
    text-decoration: none;
    color: var(--ink-3);
    font-weight: 500;
    position: relative;
    transition: color 120ms var(--ease-out);
  }
  nav a:hover {
    color: var(--ink);
  }
  nav a[aria-current='page'] {
    color: var(--ink);
  }
  nav a[aria-current='page']::after {
    content: '';
    position: absolute;
    left: var(--s3);
    right: var(--s3);
    bottom: -1px;
    height: 2px;
    border-radius: 1px;
    background: var(--seal-ink);
  }
  .tools {
    margin-left: auto;
    display: flex;
    align-items: center;
    gap: var(--s2);
  }
  .demo {
    font-size: var(--t-caption);
    font-weight: 500;
    color: var(--brass);
    background: var(--brass-wash);
    padding: 2px 8px;
    border-radius: 10px;
  }
  .who {
    position: relative;
  }
  .avatar {
    display: inline-flex;
    align-items: center;
    gap: var(--s2);
    height: 32px;
    padding: 0 var(--s2) 0 4px;
    border: 1px solid transparent;
    border-radius: 16px;
    background: transparent;
    cursor: pointer;
    color: var(--ink-2);
  }
  .avatar:hover,
  .avatar[aria-expanded='true'] {
    background: var(--rule-soft);
    color: var(--ink);
  }
  .initials {
    display: grid;
    place-items: center;
    width: 24px;
    height: 24px;
    border-radius: 50%;
    background: var(--seal-ink);
    color: var(--sheet);
    font-size: 10.5px;
    font-weight: 600;
    letter-spacing: 0.02em;
  }
  .me-name {
    max-width: 180px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .menu {
    position: absolute;
    right: 0;
    top: calc(100% + 6px);
    width: 320px;
    padding: var(--s4);
    background: var(--sheet-raised);
    border-radius: var(--r-lg);
    box-shadow: var(--lift);
    border: 1px solid var(--rule);
    transform-origin: top right;
    animation: pop 160ms var(--ease-out);
  }
  @keyframes pop {
    from {
      opacity: 0;
      transform: scale(0.96);
    }
  }
  .menu-head {
    display: grid;
    gap: 2px;
    padding-bottom: var(--s3);
    border-bottom: 1px solid var(--rule-soft);
  }
  .sub {
    color: var(--ink-3);
    font-size: 11.5px;
    word-break: break-all;
  }
  dl {
    margin: var(--s3) 0;
    display: grid;
    gap: var(--s2);
  }
  dd {
    margin: 0;
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
  }
  .tag {
    font-size: 12px;
    padding: 1px 8px;
    border-radius: 10px;
    background: var(--seal-ink-wash);
    color: var(--seal-ink);
    font-weight: 500;
  }
  .tag.role {
    background: var(--rule-soft);
    color: var(--ink-2);
    font-family: var(--font-record);
    font-size: 11.5px;
  }
  .can {
    display: grid;
    gap: var(--s1);
    padding: var(--s3) 0;
    margin-bottom: var(--s2);
    border-top: 1px solid var(--rule-soft);
    border-bottom: 1px solid var(--rule-soft);
  }
  .can ul {
    margin: 0;
    padding: 0;
    list-style: none;
    display: grid;
    gap: 3px;
    max-height: 220px;
    overflow: auto;
  }
  .can li {
    position: relative;
    padding-left: 12px;
    color: var(--ink-2);
    font-size: 12.5px;
    line-height: 1.45;
  }
  .can li::before {
    content: '';
    position: absolute;
    left: 2px;
    top: 0.6em;
    width: 4px;
    height: 4px;
    border-radius: 50%;
    background: var(--seal-ink);
  }
  .can li.sub::before {
    display: none;
  }
  .item {
    display: flex;
    align-items: center;
    gap: var(--s2);
    padding: var(--s2);
    margin: 0 calc(var(--s2) * -1);
    border-radius: var(--r-md);
    text-decoration: none;
    color: var(--ink-2);
  }
  .item:hover {
    background: var(--rule-soft);
    color: var(--seal-ink);
  }
  .signout {
    margin-bottom: calc(var(--s2) * -1);
  }
  .signout:hover {
    color: var(--wax);
  }
  @media (max-width: 720px) {
    .inner {
      gap: var(--s3);
      padding: 0 var(--s4);
    }
    .word .dim,
    .me-name,
    .demo {
      display: none;
    }
  }
  @media (max-width: 480px) {
    .inner {
      gap: var(--s2);
    }
    .word,
    .avatar :global(.icon) {
      display: none;
    }
    nav {
      min-width: 0;
      overflow-x: auto;
      scrollbar-width: none;
    }
    nav a {
      padding: 0 var(--s2);
      white-space: nowrap;
    }
    nav a[aria-current='page']::after {
      left: var(--s2);
      right: var(--s2);
      bottom: 0;
    }
  }
</style>
