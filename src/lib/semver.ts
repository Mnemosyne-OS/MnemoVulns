/**
 * semver — the one comparison OSV ranges need, without a dependency.
 *
 * OSV `SEMVER` ranges compare versions by the semver 2.0 precedence rules:
 * major.minor.patch numerically, a pre-release sorts BEFORE its release, and
 * pre-release identifiers compare numerically when both are numbers and
 * lexically otherwise. Build metadata (`+…`) is ignored.
 *
 * `0` is OSV's "since the beginning": it sorts before every version,
 * pre-releases included (`introduced: "0"`).
 */

interface Parsed {
  core: [number, number, number];
  pre: string[];
}

const SHAPE = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/;

/** Parses a version, or null when it is not semver-shaped. */
export function parseVersion(v: string): Parsed | null {
  const m = SHAPE.exec(v.trim());
  if (!m) return null;
  return { core: [Number(m[1]), Number(m[2]), Number(m[3])], pre: m[4] ? m[4].split('.') : [] };
}

function comparePre(a: string[], b: string[]): number {
  if (a.length === 0 && b.length === 0) return 0;
  if (a.length === 0) return 1; // a release sorts after its pre-releases
  if (b.length === 0) return -1;
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const x = a[i];
    const y = b[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    const xn = /^\d+$/.test(x);
    const yn = /^\d+$/.test(y);
    if (xn && yn) {
      const d = Number(x) - Number(y);
      if (d !== 0) return d < 0 ? -1 : 1;
    } else if (xn !== yn) {
      return xn ? -1 : 1; // numeric identifiers sort before alphanumeric ones
    } else if (x !== y) {
      return x < y ? -1 : 1;
    }
  }
  return 0;
}

/**
 * -1, 0 or 1. `"0"` is lower than everything. Returns null when either side
 * is not a version: the caller must not guess an order it cannot read.
 */
export function compareVersions(a: string, b: string): -1 | 0 | 1 | null {
  if (a === '0' || b === '0') return a === b ? 0 : a === '0' ? -1 : 1;
  const x = parseVersion(a);
  const y = parseVersion(b);
  if (!x || !y) return null;
  for (let i = 0; i < 3; i++) {
    if (x.core[i]! !== y.core[i]!) return x.core[i]! < y.core[i]! ? -1 : 1;
  }
  const p = comparePre(x.pre, y.pre);
  return p === 0 ? 0 : p < 0 ? -1 : 1;
}
