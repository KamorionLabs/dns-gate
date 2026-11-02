<script lang="ts">
  import type { ValidationError } from '../lib/types';
  // Shows server validation errors whose path equals `path`, or starts with it
  // when `prefix` is set (e.g. errors on list items under a chips field).
  let { errors, path, prefix = false }: { errors: ValidationError[]; path: string; prefix?: boolean } = $props();
  const mine = $derived(
    errors.filter((e) => e.path === path || (prefix && (e.path.startsWith(path + '[') || e.path.startsWith(path + '.')))),
  );
</script>

{#each mine as e, i (i)}<p class="err" id={'err-' + e.path}>{e.message}</p>{/each}

<style>
  .err {
    margin-top: 4px;
    color: var(--wax);
    font-size: 12px;
  }
  .err::before {
    content: '';
    display: inline-block;
    width: 6px;
    height: 6px;
    margin: 0 6px 1px 0;
    border-radius: 50%;
    background: var(--wax);
  }
</style>
