# MnemoVulns

Known vulnerabilities in your projects, kept in your memory and tracked from
one scan to the next.

MnemoVulns is a cartridge for [Mnemosyne OS](https://github.com/Mnemosyne-OS).
You choose a project folder. MnemoVulns reads its lockfile, asks
[OSV.dev](https://osv.dev) which installed versions have a known
vulnerability, and shows each one with the version that fixes it.

The name MnemoVulns is chosen; the trademark search is still to do.

## What it reads

| Lockfile | Versions |
|---|---|
| `pnpm-lock.yaml` | lockfile v6 and v9 |
| `package-lock.json`, `npm-shrinkwrap.json` | v1, v2 and v3 |

`yarn.lock` cannot be read yet: the host does not open `.lock` files. The
screen says so when a project only has one.

Entries with no registry version (`link:`, `file:`, git, tarball URL) cannot
be matched by OSV. They are counted on the screen.

## What a scan shows

The summary line says what was measured before it gives a count: how many
versions were asked, and whether the scan is complete.

A scan is complete only when every version was asked and every record was
read. A partial scan says it is partial above the list, and never shows "no
known vulnerability".

Each vulnerability shows:

- its severity, as the source labels it (no score is computed here);
- the version that fixes it, or "no fixed release published", or "fix not
  stated" when the record does not say;
- its source database and that database's licence;
- a link to its page on osv.dev.

Malicious packages (OpenSSF records, `MAL-…`) are listed apart.

## Tracking

Every vulnerability of a project has a state, kept in `tracking.json`:

| State | When |
|---|---|
| Open | the last scan measured an affected version |
| Risk accepted | still affected, and you wrote why you keep it |
| Fixed | a scan measured the package at a version OSV no longer names, or the package left the lockfile |
| No longer named | the same version is installed and OSV no longer names the record: the database changed, not your code |

"Fixed" is never set by a click: only a scan can measure it. A version that
was not asked (a failed request) changes nothing.

## Where things are kept

MnemoVulns never asks where to keep its files. It writes them in the folder
the host gives it inside your knowledge folder (the one you choose once in the
Hub, on the Memory Packs tab):

- `records/`: one JSON per OSV record, unchanged. A record whose date did not
  change is read from here on the next scan instead of being downloaded again.
- `projects/<project>/tracking.json` and `report.md`: the states, and the
  report of the last scan in Markdown.
- `ATTRIBUTION.md`: the sources and their licences.

Each record also enters the `osv` memory pack, once per record date. The chat
reads it when you tick MnemoVulns under Knowledge in its scope.

## Sources and licences

All data comes from the OSV.dev API. OSV.dev gathers several databases, and
each keeps its own licence (listed on
[google.github.io/osv.dev/data](https://google.github.io/osv.dev/data/)).
For npm, records come mostly from the GitHub Advisory Database
([CC-BY 4.0](https://github.com/github/advisory-database/blob/main/LICENSE.md))
and the OpenSSF Malicious Packages feed (Apache 2.0).

## Development

```bash
pnpm install
pnpm --filter @mnemosyne-plugins/mnemo-vulns dev
```

Dev server: `http://localhost:5229`.

## Licence

MIT
