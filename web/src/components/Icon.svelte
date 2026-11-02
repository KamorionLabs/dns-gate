<script lang="ts">
  type Name =
    | 'search' | 'sun' | 'moon' | 'logout' | 'copy' | 'check' | 'lock' | 'clock' | 'x' | 'chevron'
    | 'arrow' | 'human' | 'pipeline' | 'key' | 'gate' | 'alert' | 'history' | 'filter'
    | 'plus' | 'trash' | 'shield' | 'flask' | 'doc' | 'undo' | 'download';
  let { name, size = 16 }: { name: Name; size?: number } = $props();
</script>

<svg
  width={size}
  height={size}
  viewBox="0 0 16 16"
  fill="none"
  stroke="currentColor"
  stroke-width="1.5"
  stroke-linecap="round"
  stroke-linejoin="round"
  aria-hidden="true"
  class="icon"
>
  {#if name === 'search'}
    <circle cx="7" cy="7" r="4.5" /><path d="M10.5 10.5 14 14" />
  {:else if name === 'sun'}
    <circle cx="8" cy="8" r="3" /><path d="M8 1.5v1.5M8 13v1.5M1.5 8H3M13 8h1.5M3.4 3.4l1 1M11.6 11.6l1 1M3.4 12.6l1-1M11.6 4.4l1-1" />
  {:else if name === 'moon'}
    <path d="M13.5 9.5A5.5 5.5 0 0 1 6.5 2.5a5.5 5.5 0 1 0 7 7Z" />
  {:else if name === 'logout'}
    <path d="M6 2.5H3.5a1 1 0 0 0-1 1v9a1 1 0 0 0 1 1H6M10.5 11 13.5 8l-3-3M13.5 8H6" />
  {:else if name === 'copy'}
    <rect x="5.5" y="5.5" width="8" height="8" rx="1.5" /><path d="M10.5 5.5v-2a1 1 0 0 0-1-1h-6a1 1 0 0 0-1 1v6a1 1 0 0 0 1 1h2" />
  {:else if name === 'check'}
    <path d="m3 8.5 3 3 7-7" />
  {:else if name === 'lock'}
    <rect x="3" y="7" width="10" height="7" rx="1.5" /><path d="M5.5 7V5a2.5 2.5 0 0 1 5 0v2" />
  {:else if name === 'clock'}
    <circle cx="8" cy="8" r="6" /><path d="M8 4.5V8l2.5 1.5" />
  {:else if name === 'x'}
    <path d="m4 4 8 8M12 4l-8 8" />
  {:else if name === 'chevron'}
    <path d="m4.5 6.5 3.5 3.5 3.5-3.5" />
  {:else if name === 'arrow'}
    <path d="M3 8h10M9 4l4 4-4 4" />
  {:else if name === 'human'}
    <circle cx="8" cy="5" r="2.5" /><path d="M3 14c.6-2.8 2.6-4.3 5-4.3s4.4 1.5 5 4.3" />
  {:else if name === 'pipeline'}
    <circle cx="3.5" cy="8" r="1.75" /><circle cx="12.5" cy="4" r="1.75" /><circle cx="12.5" cy="12" r="1.75" /><path d="M5.2 7.3 10.8 4.7M5.2 8.7l5.6 2.6" />
  {:else if name === 'key'}
    <circle cx="5" cy="11" r="2.75" /><path d="m7 9 6-6M11 5l1.5 1.5M9.5 6.5 11 8" />
  {:else if name === 'gate'}
    <circle cx="8" cy="8" r="6" /><circle cx="8" cy="8" r="2" fill="currentColor" stroke="none" />
  {:else if name === 'alert'}
    <path d="M8 2.5 14 13H2L8 2.5Z" /><path d="M8 6.5v3M8 11.25v.01" />
  {:else if name === 'history'}
    <path d="M2.5 8a5.5 5.5 0 1 0 1.6-3.9M2.5 2.5v2.5H5M8 5.5V8l2 1.25" />
  {:else if name === 'filter'}
    <path d="M2.5 4h11M4.5 8h7M6.5 12h3" />
  {:else if name === 'plus'}
    <path d="M8 3v10M3 8h10" />
  {:else if name === 'trash'}
    <path d="M3 4.5h10M6.5 4.5V3h3v1.5M4.5 4.5l.6 8.5h5.8l.6-8.5" />
  {:else if name === 'shield'}
    <path d="M8 1.75 13 3.5v4c0 3.2-2.2 5.6-5 6.75C5.2 13.1 3 10.7 3 7.5v-4L8 1.75Z" /><path d="m5.75 8 1.6 1.6L10.5 6.5" />
  {:else if name === 'flask'}
    <path d="M6 2h4M6.5 2v4L3 13a.8.8 0 0 0 .7 1.2h8.6A.8.8 0 0 0 13 13L9.5 6V2M4.6 10h6.8" />
  {:else if name === 'doc'}
    <path d="M4 1.75h5L12.5 5v9.25h-8.5Z" /><path d="M9 1.75V5h3.5M6 8h4.5M6 10.5h4.5" />
  {:else if name === 'undo'}
    <path d="M5 4.5 2.5 7 5 9.5" /><path d="M2.5 7H10a3.5 3.5 0 0 1 0 7H7" />
  {:else if name === 'download'}
    <path d="M8 2.5v8M4.75 7.5 8 10.75l3.25-3.25M3 13.5h10" />
  {/if}
</svg>

<style>
  .icon {
    flex: none;
    display: block;
  }
</style>
