# Uninstall & rollback checklist

Manual checklist for removing or upgrading `dsh-secure-audit` without
disturbing the host profile. The plugin itself has **no install scripts and no
uninstall hooks**; its only write path is the opt-in `logFile` JSONL audit log
(append-only, disabled by default). Everything this checklist protects —
profile `package.json`, `cordis.patch.yml`, lockfiles, sessions, credentials,
other plugins — is **host-managed**, and this plugin has no code path that
touches any of it. The checklist exists because the *host operations around it*
are the risky part.

> Context for maintainers: three real accidents (2026-08-22 / 08-28 / 08-30)
> came from running `npm install` / `npm update` inside a profile directory —
> full-tree resolution pulled incompatible core-package versions and forced a
> profile rebuild. The offline procedure below is the sanctioned replacement.

## Step 0 — Before anything: back up

1. Copy the profile's `package.json`, `cordis.patch.yml` and lockfile
   (`pnpm-lock.yaml` / `package-lock.json`) to a backup directory.
2. Copy the installed plugin (`node_modules/dsh-secure-audit`) or the
   installed `file:` tgz.
3. **Sessions are not regenerable** — if the workspace's chat history matters,
   copy `~/.dsh/sessions/<workspace>/` (recommended as routine hygiene, not
   only before plugin operations).
4. Record the current state: `dsh --profile <name> --dump-config` (or
   `dsh web --dump-config`), and note plugin versions.

## Uninstall checklist

1. Remove the plugin from the profile bundle (edit `package.json` /
   `cordis.patch.yml`, or `dsh plugin remove dsh-secure-audit` if supported).
2. Remove `node_modules/dsh-secure-audit` and any `file:` tgz reference left
   in `package.json`.
3. **Do NOT run `npm install` / `npm update` in the profile directory.** Keep
   the change surgical; a full-tree resolve is how core-package versions get
   scrambled (three documented accidents).
4. Verify: `dsh --profile <name> --dump-config` no longer shows the
   `secure-audit` row, and nothing else changed.
5. Diff against the backup: sessions, `.credentials.yaml`, other plugins,
   patch file, lockfiles — all must be byte-identical except the removed row.
6. Restart the harness (or reload the web profile) and confirm the UI loads
   and the remaining plugins still work.

## Upgrade checklist (offline tarball method)

1. Prepare the tarball — `npm pack` in the repo checkout, or download the
   release asset.
2. **Verify its SHA-256** against the README *Release artifacts & integrity*
   table before touching the profile.
3. Back up (Step 0).
4. Replace **only** `node_modules/dsh-secure-audit` with the unpacked new
   version; if the profile installs from `file:<version>.tgz`, drop the new
   tgz into place and update that one reference. Never trigger dependency
   resolution.
5. Verify: `dsh --profile <name> --dump-config` shows a clean `secure-audit`
   row (id/name match the new version).
6. Restart, then re-run `security_audit` plus a quick scan/redact smoke test.

## Rollback checklist

1. Restore the Step 0 backup: `package.json`, `cordis.patch.yml`,
   lockfiles, `node_modules/dsh-secure-audit`.
2. `dsh --profile <name> --dump-config` — versions must match the pre-change
   state.
3. Restart and re-verify the plugin loads and the tools respond.

## Interpreting results

- `allow` means "no rule fired", not "safe" (see README *Limitations*).
- A clean `dump-config` means the bundle loaded. Run `security_audit` for a
  posture snapshot of the machine — it is not a certification.
