/**
 * lockfile — the installed versions a project's lockfiles record, per ecosystem.
 *
 * Read (doc 135 §3sexies):
 *  - npm: `pnpm-lock.yaml` (v6, v9; the pattern measured 327 / 327 against
 *    `pnpm audit` on 2026-10-04), `package-lock.json` / `npm-shrinkwrap.json`
 *    (v1-v3), `yarn.lock` (v1 and berry);
 *  - PyPI: `Pipfile.lock`, `poetry.lock`, `uv.lock`, `requirements.txt`
 *    (pinned `==` lines only);
 *  - crates.io: `Cargo.lock`.
 *
 * 🚨 What cannot be asked about is COUNTED, never dropped: a `link:`, `file:`,
 * git, tarball or workspace entry has no registry version, and an unpinned
 * requirement has no version at all. A scan that hid them would read as
 * "these were checked".
 *
 * Ecosystem names are OSV's, exactly: measured on 2026-10-04, one query with
 * `pypi` instead of `PyPI` makes OSV refuse the WHOLE batch.
 */

export type Ecosystem = 'npm' | 'PyPI' | 'crates.io' | 'Go' | 'Packagist' | 'RubyGems';
/** Ecosystems whose lockfiles are read, in display order (OSV's spellings, exactly). */
export const ECOSYSTEMS: readonly Ecosystem[] = ['npm', 'PyPI', 'crates.io', 'Go', 'Packagist', 'RubyGems'];
/** The ecosystems the host can keep a local database of; the others are always asked online. */
export type MirrorEcosystem = 'npm' | 'PyPI' | 'crates.io';
export const MIRROR_ECOSYSTEMS: readonly MirrorEcosystem[] = ['npm', 'PyPI', 'crates.io'];

export type LockKind = 'pnpm' | 'npm' | 'yarn' | 'pipfile' | 'poetry' | 'uv' | 'requirements' | 'cargo' | 'gomod' | 'composer' | 'gemfile';

export interface InstalledPackage {
  ecosystem: Ecosystem;
  name: string;
  version: string;
  /**
   * true = the lockfile DECLARES it for development only; false = reachable
   * from a production dependency; ABSENT = the lockfile does not say (yarn,
   * requirements.txt, Cargo.lock, uv.lock). Never a filter: on an Electron app
   * the runtime itself is a devDependency, and it ships.
   */
  dev?: boolean;
}

export interface SkippedPackage {
  ecosystem: Ecosystem;
  name: string;
  spec: string;
}

export interface LockfileRead {
  kind: LockKind;
  ecosystem: Ecosystem;
  /** Unique name@version pairs that OSV can be asked about, sorted. */
  packages: InstalledPackage[];
  /** Entries with no pinned registry version, unique, sorted. */
  skipped: SkippedPackage[];
  /**
   * The dependency graph, when the lockfile records one (pnpm v9). ABSENT
   * when it does not: no "pulled by" line is shown then, never a guessed one.
   */
  graph?: DepGraph;
}

/** One way a package is reached: a workspace package, and the direct dependency it starts from. */
export interface Via {
  /** The workspace package, as the lockfile names it (`.` is the root, `apps/web`). */
  importer: string;
  /** The importer's direct dependency the path starts from (the package itself when direct). */
  through: string;
  /** The importer declares `through` in devDependencies, and it is not the app's runtime. */
  dev: boolean;
  /** `through` is declared for development but packed into the app as its runtime (Electron). */
  runtime?: true;
}

/** A lockfile's graph: the importers' direct dependencies and the edges between versions. */
export interface DepGraph {
  /**
   * `runtime`: the importer declares this dependency for development, but a
   * packager it also declares puts it INSIDE the app (see RUNTIME_PACKAGERS).
   * Only that version ships; what it depends on stays as declared.
   */
  roots: { importer: string; through: string; id: string; dev: boolean; runtime?: true }[];
  /** Snapshot id (peers included) -> the snapshot ids it depends on. */
  edges: Map<string, string[]>;
}

/**
 * Lockfile names, by ecosystem, in the order they are preferred when a folder
 * has several for the SAME ecosystem. A folder with lockfiles of two
 * ecosystems is read for both.
 */
export const LOCKFILES: readonly { file: string; kind: LockKind; ecosystem: Ecosystem }[] = [
  { file: 'pnpm-lock.yaml', kind: 'pnpm', ecosystem: 'npm' },
  { file: 'package-lock.json', kind: 'npm', ecosystem: 'npm' },
  { file: 'npm-shrinkwrap.json', kind: 'npm', ecosystem: 'npm' },
  { file: 'yarn.lock', kind: 'yarn', ecosystem: 'npm' },
  { file: 'Pipfile.lock', kind: 'pipfile', ecosystem: 'PyPI' },
  { file: 'poetry.lock', kind: 'poetry', ecosystem: 'PyPI' },
  { file: 'uv.lock', kind: 'uv', ecosystem: 'PyPI' },
  { file: 'requirements.txt', kind: 'requirements', ecosystem: 'PyPI' },
  { file: 'Cargo.lock', kind: 'cargo', ecosystem: 'crates.io' },
  // go.mod and not go.sum: go.sum lists every version the build CONSULTED, go.mod the ones it selected.
  { file: 'go.mod', kind: 'gomod', ecosystem: 'Go' },
  { file: 'composer.lock', kind: 'composer', ecosystem: 'Packagist' },
  { file: 'Gemfile.lock', kind: 'gemfile', ecosystem: 'RubyGems' },
];

/** A version OSV can be asked about, per ecosystem. */
const REGISTRY_VERSION: Record<Ecosystem, RegExp> = {
  'npm': /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/,
  'crates.io': /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/,
  // PEP 440, loosely: a release number, then any pre/post/dev/local suffix.
  'PyPI': /^\d+(?:\.\d+)*(?:[a-zA-Z0-9.!+_-]*)$/,
  // Go modules: v-prefixed semver, pseudo-versions and +incompatible included.
  'Go': /^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/,
  // Composer: a numbered release, `v` optional; `dev-main` is a branch, not a release.
  'Packagist': /^v?\d+(?:\.\d+)*(?:-[0-9A-Za-z.]+)?$/,
  // Gem versions: dotted segments, letters allowed (`1.0.0.pre1`).
  'RubyGems': /^\d+(?:\.[0-9A-Za-z]+)*$/,
};

/** Thrown when the text is not the lockfile it claims to be. The screen says "unreadable", never zero. */
export class LockfileError extends Error {
  constructor(public readonly code: 'NOT_A_LOCKFILE' | 'UNSUPPORTED_VERSION' | 'NOT_JSON', detail?: string) {
    super(detail ? `${code}: ${detail}` : code);
    this.name = 'LockfileError';
  }
}

class Collector {
  private ok = new Map<string, InstalledPackage>();
  private skip = new Map<string, SkippedPackage>();

  constructor(private ecosystem: Ecosystem) {}

  add(name: string, spec: string, dev?: boolean): void {
    if (!name) return;
    if (!REGISTRY_VERSION[this.ecosystem].test(spec)) { this.skip.set(`${name}@${spec}`, { ecosystem: this.ecosystem, name, spec }); return; }
    const key = `${name}@${spec}`;
    const prev = this.ok.get(key);
    // The same version reached from production and from development is production.
    const merged = prev?.dev === false || dev === false ? false : prev?.dev === true || dev === true ? true : undefined;
    this.ok.set(key, { ecosystem: this.ecosystem, name, version: spec, ...(merged === undefined ? {} : { dev: merged }) });
  }

  /** An entry that is not a registry version whatever its text (workspace member, path, git). */
  skipped(name: string, spec: string): void {
    if (name) this.skip.set(`${name}@${spec}`, { ecosystem: this.ecosystem, name, spec });
  }

  result(kind: LockKind): LockfileRead {
    const byKey = <T>(m: Map<string, T>) =>
      [...m.entries()].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0)).map(([, v]) => v);
    return { kind, ecosystem: this.ecosystem, packages: byKey(this.ok), skipped: byKey(this.skip) };
  }
}

/**
 * Splits `name@spec` where the name may be scoped (`@scope/name@1.2.3`).
 * The spec keeps everything after the separating `@`, peer suffix removed.
 */
function splitKey(key: string): { name: string; spec: string } | null {
  const at = key.indexOf('@', key.startsWith('@') ? 1 : 0);
  if (at <= 0) return null;
  const name = key.slice(0, at);
  // pnpm writes peer resolutions after the version: `react-dom@18.3.1(react@18.3.1)`.
  const spec = key.slice(at + 1).replace(/\(.*$/, '');
  return { name, spec };
}

// ── npm ─────────────────────────────────────────────────────────────────

/** Reads a pnpm lockfile (v6 or v9). */
export function readPnpmLock(text: string): LockfileRead {
  const version = /^lockfileVersion:\s*'?([\d.]+)'?/m.exec(text)?.[1];
  if (!version) throw new LockfileError('NOT_A_LOCKFILE', 'no lockfileVersion');
  const major = Number.parseInt(version, 10);
  if (major !== 6 && major !== 9) throw new LockfileError('UNSUPPORTED_VERSION', `pnpm lockfile ${version}`);

  const start = text.search(/^packages:\s*$/m);
  if (start < 0) {
    // A project with no dependency at all has no `packages:` block: that is a real empty list.
    return { kind: 'pnpm', ecosystem: 'npm', packages: [], skipped: [] };
  }
  const rest = text.slice(start);
  // The block ends at the next top-level key (v9: `snapshots:`). Searched for
  // AFTER a newline: a `^` anchor would match the block's own first line.
  const end = rest.search(/\n[A-Za-z]/);
  const block = end < 0 ? rest : rest.slice(0, end + 1);

  const c = new Collector('npm');
  const graph = major === 9 ? pnpmGraph(text) : null;
  const devOf = graph ? devFlagsOf(graph) : null;
  // Two-space indented keys, quoted or not, v6 with a leading slash.
  for (const m of block.matchAll(/^ {2}'?\/?([^\s':][^']*?)'?:\s*$/gm)) {
    const parts = splitKey(m[1]!);
    if (parts) c.add(parts.name, parts.spec, devOf?.get(`${parts.name}@${parts.spec}`));
  }
  return { ...c.result('pnpm'), ...(graph ? { graph } : {}) };
}

/** The lines of one top-level section of a pnpm lockfile (`importers:`, `snapshots:`). */
function pnpmSection(text: string, name: string): string[] {
  const start = text.search(new RegExp(`^${name}:\\s*$`, 'm'));
  if (start < 0) return [];
  const rest = text.slice(start);
  const end = rest.search(/\n[A-Za-z]/);
  return (end < 0 ? rest : rest.slice(0, end + 1)).split(/\r?\n/).slice(1);
}

const unquote = (k: string) => k.replace(/^'|'$/g, '');

/**
 * Which name@version a pnpm v9 lockfile reaches ONLY through devDependencies.
 *
 * Every importer (every package of the workspace) is a root: its
 * `dependencies` and `optionalDependencies` reach production, its
 * `devDependencies` reach development. The edges are the `snapshots:`
 * entries. A version reached from both is production. A version reached from
 * neither is left out of the map (unknown), never guessed.
 */
export function pnpmDevFlags(text: string): Map<string, boolean> {
  return devFlagsOf(pnpmGraph(text));
}

/**
 * The snapshot id a dependency points at. A plain spec is a version
 * (`6.0.0(react@18.3.1)`): the id is `dep@spec`. An ALIAS (`npm:` in a
 * package.json) is written by pnpm as the real `name@version`
 * (`react-loadable: '@docusaurus/react-loadable@6.0.0(react@18.3.1)'`): that
 * is the id itself. Read as `dep@spec` it named no snapshot, so the package
 * was pulled by nobody and its place was unknown.
 */
function specId(dep: string, spec: string): string {
  return /^(?:@[^@\s/]+\/)?[^@\s\d(][^@\s(]*@\d/.test(spec) ? spec : `${dep}@${spec}`;
}

/** Reads the importers and the `snapshots:` edges of a pnpm v9 lockfile. */
export function pnpmGraph(text: string): DepGraph {
  const roots: DepGraph['roots'] = [];
  let importer: string | null = null;
  let group: string | null = null;
  let dep: string | null = null;
  for (const line of pnpmSection(text, 'importers')) {
    const m2 = /^ {2}('?[^\s'][^']*'?):\s*$/.exec(line);
    if (m2) { importer = unquote(m2[1]!); group = null; continue; }
    const m4 = /^ {4}(\w+):\s*$/.exec(line);
    if (m4) { group = m4[1]!; continue; }
    const m6 = /^ {6}('?[^\s'][^']*'?):\s*$/.exec(line);
    if (m6) { dep = unquote(m6[1]!); continue; }
    const v = /^ {8}version:\s*(\S+)\s*$/.exec(line);
    if (v && dep && group && importer !== null && !v[1]!.startsWith('link:')) {
      const id = specId(dep, unquote(v[1]!));
      if (group === 'devDependencies') roots.push({ importer, through: dep, id, dev: true });
      else if (group === 'dependencies' || group === 'optionalDependencies') roots.push({ importer, through: dep, id, dev: false });
    }
  }

  const edges = new Map<string, string[]>();
  let node: string | null = null;
  let inDeps = false;
  for (const line of pnpmSection(text, 'snapshots')) {
    const k = /^ {2}('?[^\s'][^']*'?):/.exec(line);
    if (k) { node = unquote(k[1]!); edges.set(node, []); inDeps = false; continue; }
    const g = /^ {4}(\w+):\s*$/.exec(line);
    if (g) { inDeps = g[1] === 'dependencies' || g[1] === 'optionalDependencies'; continue; }
    const e = /^ {6}('?[^\s'][^']*'?):\s*(\S+)\s*$/.exec(line);
    if (e && node && inDeps && !e[2]!.startsWith('link:')) edges.get(node)!.push(specId(unquote(e[1]!), unquote(e[2]!)));
  }
  // An Electron app declares its runtime as a devDependency, and the packager
  // copies it into the installer: that version ships. Its own dependencies
  // (`@electron/get`, `extract-zip`) only download it, and stay as declared.
  // The packager counts in the same importer, or at the workspace root, where
  // a monorepo often keeps its build tools for every app.
  const packs = new Set(roots.filter((r) => RUNTIME_PACKAGERS.includes(r.through)).map((r) => r.importer));
  for (const root of roots) if (root.through === 'electron' && (packs.has(root.importer) || packs.has('.'))) root.runtime = true;
  return { roots, edges };
}

/** Packagers that copy the `electron` runtime into what they build. */
export const RUNTIME_PACKAGERS: readonly string[] = ['electron-builder', '@electron-forge/cli', 'electron-packager'];

/** A snapshot id without its peer suffix: `react-dom@18.3.1(react@18.3.1)` -> `react-dom@18.3.1`. */
function bareId(id: string): string {
  const p = splitKey(id);
  return p ? `${p.name}@${p.spec}` : id;
}

/** Which name@version the graph reaches ONLY through devDependencies (see pnpmDevFlags). */
function devFlagsOf(graph: DepGraph): Map<string, boolean> {
  const { edges } = graph;
  const prodRoots = graph.roots.filter((r) => !r.dev).map((r) => r.id);
  const devRoots = graph.roots.filter((r) => r.dev).map((r) => r.id);
  const walk = (roots: string[]) => {
    const seen = new Set<string>();
    const stack = [...roots];
    while (stack.length) {
      const id = stack.pop()!;
      if (seen.has(id)) continue;
      seen.add(id);
      for (const n of edges.get(id) ?? []) stack.push(n);
    }
    return seen;
  };
  // A snapshot id carries its peers (`react-dom@18.3.1(react@18.3.1)`); the package key does not.
  const bare = (ids: Set<string>) => new Set([...ids].map(bareId));
  const prod = bare(walk(prodRoots));
  const dev = bare(walk(devRoots));
  const out = new Map<string, boolean>();
  for (const id of dev) out.set(id, !prod.has(id));
  for (const id of prod) out.set(id, false);
  // A runtime packed into the app ships, whatever its declaration (its dependencies do not).
  for (const r of graph.roots) if (r.runtime) out.set(bareId(r.id), false);
  return out;
}

/**
 * Who pulls each of `targets` (bare `name@version`): one entry per importer
 * and direct dependency a path starts from. Production entries sort first,
 * then by importer and dependency name. A target the graph never reaches is
 * left out of the map: the screen shows nothing for it, never a guess.
 */
export function viaOf(graph: DepGraph, targets: ReadonlySet<string>): Map<string, Via[]> {
  const found = new Map<string, Map<string, Via>>();
  if (targets.size === 0) return new Map();
  for (const root of graph.roots) {
    const seen = new Set<string>();
    const stack = [root.id];
    while (stack.length) {
      const id = stack.pop()!;
      if (seen.has(id)) continue;
      seen.add(id);
      const key = bareId(id);
      if (targets.has(key)) {
        const byWay = found.get(key) ?? new Map<string, Via>();
        const way = `${root.importer}\u0000${root.through}`;
        const prev = byWay.get(way);
        // The same dependency declared both ways is production.
        const runtime = root.runtime === true && key === bareId(root.id);
        const dev = root.dev && !runtime;
        if (!prev || (prev.dev && !dev)) byWay.set(way, { importer: root.importer, through: root.through, dev, ...(runtime ? { runtime: true as const } : {}) });
        found.set(key, byWay);
      }
      for (const n of graph.edges.get(id) ?? []) if (!seen.has(n)) stack.push(n);
    }
  }
  const order = (a: Via, b: Via) =>
    Number(a.dev) - Number(b.dev) || a.importer.localeCompare(b.importer) || a.through.localeCompare(b.through);
  return new Map([...found].map(([k, m]) => [k, [...m.values()].sort(order)]));
}

/** Reads a package-lock.json or npm-shrinkwrap.json (v1, v2, v3). */
export function readNpmLock(text: string): LockfileRead {
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch (err) {
    throw new LockfileError('NOT_JSON', err instanceof Error ? err.message : String(err));
  }
  if (!json || typeof json !== 'object') throw new LockfileError('NOT_A_LOCKFILE');
  const lock = json as Record<string, unknown>;
  const c = new Collector('npm');

  if (lock.packages && typeof lock.packages === 'object') {
    for (const [p, v] of Object.entries(lock.packages as Record<string, unknown>)) {
      if (p === '' || !v || typeof v !== 'object') continue; // '' is the project itself
      const entry = v as Record<string, unknown>;
      const idx = p.lastIndexOf('node_modules/');
      // A workspace member (`packages/foo`) is the project's own code, not a dependency.
      if (idx < 0) continue;
      const name = typeof entry.name === 'string' && entry.name ? entry.name : p.slice(idx + 'node_modules/'.length);
      if (entry.link === true) {
        c.add(name, `link:${typeof entry.resolved === 'string' ? entry.resolved : ''}`);
        continue;
      }
      const resolved = typeof entry.resolved === 'string' ? entry.resolved : '';
      const ver = typeof entry.version === 'string' ? entry.version : '';
      // A git or file dependency carries a URL where a registry version would be.
      c.add(name, resolved.startsWith('git') || resolved.startsWith('file:') ? resolved : ver, entry.dev === true || entry.devOptional === true);
    }
    return c.result('npm');
  }

  if (lock.dependencies && typeof lock.dependencies === 'object') {
    const walk = (deps: Record<string, unknown>) => {
      for (const [name, v] of Object.entries(deps)) {
        if (!v || typeof v !== 'object') continue;
        const entry = v as Record<string, unknown>;
        c.add(name, typeof entry.version === 'string' ? entry.version : '', entry.dev === true);
        if (entry.dependencies && typeof entry.dependencies === 'object') walk(entry.dependencies as Record<string, unknown>);
      }
    };
    walk(lock.dependencies as Record<string, unknown>);
    return c.result('npm');
  }

  if (typeof lock.lockfileVersion === 'number') return { kind: 'npm', ecosystem: 'npm', packages: [], skipped: [] };
  throw new LockfileError('NOT_A_LOCKFILE', 'no packages and no dependencies');
}

/**
 * Reads a yarn.lock, v1 or berry. An entry is a header line of specs
 * (`"lodash@^4.17.0", lodash@^4.17.21:`) and an indented body with its
 * `version`. Berry adds `resolution: "name@npm:1.2.3"`, whose protocol says
 * whether it came from the registry (`npm:`) or not (`workspace:`, `patch:`,
 * `file:`, `link:`, git).
 */
export function readYarnLock(text: string): LockfileRead {
  const berry = /^__metadata:/m.test(text);
  if (!berry && !/^# yarn lockfile v1/m.test(text)) throw new LockfileError('NOT_A_LOCKFILE', 'no yarn lockfile header');
  const c = new Collector('npm');
  const blocks = text.split(/\r?\n(?=\S)/);
  for (const block of blocks) {
    const lines = block.split(/\r?\n/);
    const header = lines[0]!;
    if (!header.endsWith(':') || header.startsWith('#') || header.startsWith('__metadata')) continue;
    const firstSpec = header.slice(0, -1).split(',')[0]!.trim().replace(/^"|"$/g, '');
    const parts = splitKey(firstSpec);
    if (!parts) continue;
    const version = /^\s+version:?\s+"?([^"\s]+)"?/m.exec(block)?.[1] ?? '';
    if (berry) {
      const resolution = /^\s+resolution:\s+"?([^"\n]+)"?/m.exec(block)?.[1] ?? '';
      const proto = splitKey(resolution)?.spec ?? '';
      if (!proto.startsWith('npm:')) { c.skipped(parts.name, proto || parts.spec); continue; }
    } else {
      const resolved = /^\s+resolved\s+"([^"]+)"/m.exec(block)?.[1] ?? '';
      if (resolved && !/^https?:\/\//.test(resolved)) { c.skipped(parts.name, resolved); continue; }
      if (/^(file|link|git|github):/.test(parts.spec)) { c.skipped(parts.name, parts.spec); continue; }
    }
    c.add(parts.name, version);
  }
  return c.result('yarn');
}

// ── PyPI ────────────────────────────────────────────────────────────────

/** Reads a Pipfile.lock: `default` and `develop`, each `{ name: { version: "==1.2.3" } }`. */
export function readPipfileLock(text: string): LockfileRead {
  let json: Record<string, unknown>;
  try { json = JSON.parse(text) as Record<string, unknown>; } catch (err) {
    throw new LockfileError('NOT_JSON', err instanceof Error ? err.message : String(err));
  }
  if (!json || typeof json !== 'object' || (!json.default && !json.develop)) throw new LockfileError('NOT_A_LOCKFILE', 'no default or develop section');
  const c = new Collector('PyPI');
  for (const section of ['default', 'develop']) {
    const deps = json[section];
    if (!deps || typeof deps !== 'object') continue;
    for (const [name, v] of Object.entries(deps as Record<string, unknown>)) {
      const entry = (v ?? {}) as Record<string, unknown>;
      const ver = typeof entry.version === 'string' ? entry.version : '';
      if (ver.startsWith('==')) c.add(name, ver.slice(2), section === 'develop');
      else c.skipped(name, typeof entry.git === 'string' ? `git+${entry.git}` : typeof entry.path === 'string' ? `path:${entry.path}` : ver || 'unpinned');
    }
  }
  return c.result('pipfile');
}

/**
 * The `[[package]]` tables of a TOML lockfile (poetry.lock, uv.lock,
 * Cargo.lock), with the string keys this module needs. Not a TOML parser: it
 * reads `key = "value"` lines and inline tables of one level, which is all
 * these three files write for name, version and source.
 */
function tomlPackages(text: string): Record<string, string>[] {
  const out: Record<string, string>[] = [];
  const blocks = text.split(/^\[\[package\]\]\s*$/m).slice(1);
  for (const block of blocks) {
    const body = block.split(/^\[/m)[0]!; // stop at the next table
    const rec: Record<string, string> = {};
    // Strings, inline tables and inline arrays (poetry 2.x writes `groups = ["main"]`).
    for (const m of body.matchAll(/^([A-Za-z0-9_-]+)\s*=\s*(".*?"|\{.*\}|\[.*\])\s*$/gm)) {
      rec[m[1]!] = m[2]!.startsWith('"') ? m[2]!.slice(1, -1) : m[2]!;
    }
    out.push(rec);
  }
  return out;
}

/** poetry 1.x writes `category = "dev"`, poetry 2.x `groups = ["main", …]`; neither = unknown. */
function poetryDev(p: Record<string, string>): boolean | undefined {
  if (p.category) return p.category === 'dev';
  if (p.groups) return !/"main"/.test(p.groups);
  return undefined;
}

/** Reads a poetry.lock. A package from git, a path or a URL carries a `[package.source]` table. */
export function readPoetryLock(text: string): LockfileRead {
  if (!/^\[\[package\]\]/m.test(text)) throw new LockfileError('NOT_A_LOCKFILE', 'no [[package]] table');
  const c = new Collector('PyPI');
  const blocks = text.split(/^\[\[package\]\]\s*$/m).slice(1);
  tomlPackages(text).forEach((p, i) => {
    const source = /^\[package\.source\]\s*$[\s\S]*?^type\s*=\s*"([^"]+)"/m.exec(blocks[i] ?? '')?.[1];
    if (source && source !== 'legacy') c.skipped(p.name ?? '', `${source}:${p.version ?? ''}`);
    else c.add(p.name ?? '', p.version ?? '', poetryDev(p));
  });
  return c.result('poetry');
}

/** Reads a uv.lock. Only `source = { registry = … }` packages come from an index. */
export function readUvLock(text: string): LockfileRead {
  if (!/^\[\[package\]\]/m.test(text)) throw new LockfileError('NOT_A_LOCKFILE', 'no [[package]] table');
  const c = new Collector('PyPI');
  for (const p of tomlPackages(text)) {
    const source = p.source ?? '';
    if (source.includes('registry')) c.add(p.name ?? '', p.version ?? '');
    else c.skipped(p.name ?? '', source.replace(/[{}\s"]/g, '') || 'no source');
  }
  return c.result('uv');
}

/**
 * Reads a requirements.txt. Only exact pins (`name==1.2.3`) say what is
 * installed; every other line that names a package is counted as unpinned.
 * Options (`-r`, `--hash`, `-e`), comments and blank lines are not packages.
 */
export function readRequirements(text: string): LockfileRead {
  const c = new Collector('PyPI');
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/\s+#.*$/, '').replace(/\\$/, '').trim();
    if (!line || line.startsWith('#')) continue;
    if (line.startsWith('-')) {
      // -e git+…#egg=name is an editable install of someone's code: counted.
      const egg = /#egg=([A-Za-z0-9._-]+)/.exec(line)?.[1];
      if (egg) c.skipped(egg, line.split(/\s+/).slice(1).join(' '));
      continue;
    }
    const req = line.split(';')[0]!.trim(); // environment marker
    const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(.*)$/.exec(req);
    if (!m) continue;
    const pin = /^===?\s*([^\s,]+)$/.exec(m[2]!.trim());
    if (pin && !pin[1]!.includes('*')) c.add(m[1]!, pin[1]!);
    else c.skipped(m[1]!, m[2]!.trim() || 'unpinned');
  }
  return c.result('requirements');
}

// ── crates.io ───────────────────────────────────────────────────────────

/** Reads a Cargo.lock. A package with no `source` is a member of the workspace (the project's own code). */
export function readCargoLock(text: string): LockfileRead {
  if (!/^\[\[package\]\]/m.test(text)) throw new LockfileError('NOT_A_LOCKFILE', 'no [[package]] table');
  const c = new Collector('crates.io');
  for (const p of tomlPackages(text)) {
    const source = p.source ?? '';
    if (source.startsWith('registry+')) c.add(p.name ?? '', p.version ?? '');
    else if (source) c.skipped(p.name ?? '', source);
    // No source: a crate of this workspace. Not a dependency, not counted.
  }
  return c.result('cargo');
}

// ── Go ───────────────────────────────────────────────────────────────────

/** Reads a go.mod: the module versions the build selected. A `replace` pointing at a path is the person's own code. */
export function readGoMod(text: string): LockfileRead {
  if (!/^module\s+\S+/m.test(text)) throw new LockfileError('NOT_A_LOCKFILE', 'no module line');
  const c = new Collector('Go');
  const lines = text.split(/\r?\n/).map((l) => l.replace(/\/\/.*$/, '').trim());
  let block: 'require' | 'replace' | null = null;
  const local = new Set<string>();
  const reqs: [string, string][] = [];
  for (const line of lines) {
    if (!line) continue;
    if (block && line === ')') { block = null; continue; }
    const open = /^(require|replace|exclude|retract)\s*\($/.exec(line);
    if (open) { block = open[1] === 'require' || open[1] === 'replace' ? open[1] : null; continue; }
    const one = /^(require|replace)\s+(.*)$/.exec(line);
    const kind = one ? one[1] : block;
    const body = one ? one[2]! : line;
    if (kind === 'require') {
      const m = /^(\S+)\s+(\S+)/.exec(body);
      if (m) reqs.push([m[1]!, m[2]!]);
    } else if (kind === 'replace') {
      const m = /^(\S+)(?:\s+\S+)?\s+=>\s+(\S+)(?:\s+(\S+))?/.exec(body);
      if (m && !m[3]) local.add(m[1]!);
    }
  }
  for (const [name, version] of reqs) {
    if (local.has(name)) c.skipped(name, 'replace => local path');
    else c.add(name, version);
  }
  return c.result('gomod');
}

// ── Packagist (PHP) ─────────────────────────────────────────────────────

/** Reads a composer.lock: `packages` ship, `packages-dev` are declared for development. */
export function readComposerLock(text: string): LockfileRead {
  let json: unknown;
  try { json = JSON.parse(text); } catch (err) { throw new LockfileError('NOT_JSON', err instanceof Error ? err.message : String(err)); }
  const o = json as { packages?: unknown; 'packages-dev'?: unknown };
  if (!o || typeof o !== 'object' || !Array.isArray(o.packages)) throw new LockfileError('NOT_A_LOCKFILE', 'no packages list');
  const c = new Collector('Packagist');
  const take = (list: unknown, dev: boolean) => {
    for (const p of Array.isArray(list) ? list : []) {
      const { name, version } = (p ?? {}) as { name?: unknown; version?: unknown };
      if (typeof name === 'string' && typeof version === 'string') c.add(name, version, dev);
    }
  };
  take(o.packages, false);
  take(o['packages-dev'], true);
  return c.result('composer');
}

// ── RubyGems ────────────────────────────────────────────────────────────

/**
 * Reads a Gemfile.lock: the gems under `specs:` of each GEM section (four
 * spaces of indent; deeper lines are their dependencies). A platform suffix
 * (`nokogiri (1.13.0-x86_64-linux)`) is not part of the version. GIT and
 * PATH sections are someone's code, counted and not asked.
 */
export function readGemfileLock(text: string): LockfileRead {
  if (!/^(GEM|GIT|PATH)\s*$/m.test(text)) throw new LockfileError('NOT_A_LOCKFILE', 'no GEM section');
  const c = new Collector('RubyGems');
  let section = '';
  let inSpecs = false;
  for (const raw of text.split(/\r?\n/)) {
    if (/^\S/.test(raw)) { section = raw.trim(); inSpecs = false; continue; }
    if (/^ {2}specs:\s*$/.test(raw)) { inSpecs = true; continue; }
    if (/^ {2}\S/.test(raw)) { inSpecs = false; continue; }
    const m = inSpecs ? /^ {4}([^\s(]+) \(([^)]+)\)\s*$/.exec(raw) : null;
    if (!m) continue;
    const version = m[2]!.replace(/-(?:x86|x64|arm|aarch|java|universal|mingw|mswin|darwin|linux|i386|i686|ruby)[\w.-]*$/, '');
    if (section === 'GEM') c.add(m[1]!, version);
    else c.skipped(m[1]!, `${section.toLowerCase()}: ${version}`);
  }
  return c.result('gemfile');
}

/** Reads a lockfile by its kind. */
export function readLockfile(kind: LockKind, text: string): LockfileRead {
  switch (kind) {
    case 'pnpm': return readPnpmLock(text);
    case 'npm': return readNpmLock(text);
    case 'yarn': return readYarnLock(text);
    case 'pipfile': return readPipfileLock(text);
    case 'poetry': return readPoetryLock(text);
    case 'uv': return readUvLock(text);
    case 'requirements': return readRequirements(text);
    case 'cargo': return readCargoLock(text);
    case 'gomod': return readGoMod(text);
    case 'composer': return readComposerLock(text);
    case 'gemfile': return readGemfileLock(text);
  }
}

/** The lockfile to read for EACH ecosystem present in the folder, preferred one first. */
export function pickLockfiles(names: readonly string[]): { file: string; kind: LockKind; ecosystem: Ecosystem }[] {
  const set = new Set(names);
  const out: { file: string; kind: LockKind; ecosystem: Ecosystem }[] = [];
  for (const eco of ECOSYSTEMS) {
    const first = LOCKFILES.find((l) => l.ecosystem === eco && set.has(l.file));
    if (first) out.push(first);
  }
  return out;
}
