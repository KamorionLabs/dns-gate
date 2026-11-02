// Minimal YAML emitter for policy documents (read-only preview of a draft).

const plain = /^[A-Za-z0-9_./@:-][A-Za-z0-9_ ./@:*-]*$/;
const reserved = /^(true|false|null|yes|no|on|off|~|-?\d+(\.\d+)?)$/i;

function scalar(v: unknown): string {
  if (v === null || v === undefined) return 'null';
  if (typeof v === 'boolean' || typeof v === 'number') return String(v);
  const s = String(v);
  if (s !== '' && plain.test(s) && !reserved.test(s) && !s.endsWith(' ') && !s.includes(': ')) return s;
  return JSON.stringify(s);
}

function isEmpty(v: unknown): boolean {
  return (
    v === undefined ||
    v === null ||
    v === '' ||
    v === false ||
    (Array.isArray(v) && v.length === 0) ||
    (typeof v === 'object' && !Array.isArray(v) && Object.keys(v as object).length === 0)
  );
}

function emit(v: unknown, indent: number, out: string[], keepEmpty = false): void {
  const pad = '  '.repeat(indent);
  if (Array.isArray(v)) {
    for (const item of v) {
      if (item !== null && typeof item === 'object' && !Array.isArray(item)) {
        const lines: string[] = [];
        emit(item, indent + 1, lines);
        const first = lines[0] ?? '  '.repeat(indent + 1) + '{}';
        out.push(pad + '- ' + first.trimStart(), ...lines.slice(1));
      } else {
        out.push(pad + '- ' + scalar(item));
      }
    }
    return;
  }
  if (v !== null && typeof v === 'object') {
    for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
      if (!keepEmpty && isEmpty(val) && val !== 0) continue;
      if (Array.isArray(val) && val.every((x) => typeof x !== 'object' || x === null) && val.length <= 6) {
        out.push(`${pad}${scalar(k)}: [${val.map(scalar).join(', ')}]`);
      } else if (val !== null && typeof val === 'object') {
        if (isEmpty(val)) {
          out.push(`${pad}${scalar(k)}: ${Array.isArray(val) ? '[]' : '{}'}`);
          continue;
        }
        out.push(`${pad}${scalar(k)}:`);
        emit(val, indent + 1, out);
      } else {
        out.push(`${pad}${scalar(k)}: ${scalar(val)}`);
      }
    }
    return;
  }
  out.push(pad + scalar(v));
}

export function toYAML(doc: object): string {
  const out: string[] = [];
  for (const [k, v] of Object.entries(doc)) {
    if (isEmpty(v)) {
      out.push(`${k}: ${Array.isArray(v) ? '[]' : '{}'}`);
      continue;
    }
    out.push(`${k}:`);
    emit(v, 1, out);
  }
  return out.join('\n') + '\n';
}
