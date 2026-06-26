# Feature manifest

This repo publishes `.revengai/features.json`, a machine-readable manifest listing which
RevEng.AI features this plugin supports. It is generated from code and committed so it is
available at every release tag.

## Source of truth

Feature support is declared in [`scripts/emit_features.py`](../scripts/emit_features.py):

- `ACTIONS` maps the plugin's user-facing actions/components (registered in
  `src/main/java/ai/reveng/toolkit/ghidra/plugins/` and the binary-similarity UI) to a
  `feature_id` + status.
- `EXTRA` declares features not tied to a single action (binary upload, the function-search
  filters, comment/data-type sync, etc.).
- `build_manifest()` merges the two.

`.revengai/features.json` is generated from this script — never edit the JSON by hand. The
script is build tooling (a small Python script, like `.github/scripts/bump_revengai.py`)
and is not part of the Ghidra extension under `src/`.

## Status values

`yes`, `partial`, `poc`, `wip`, `planned`, `absent`. A feature may carry an optional `note`
(<=200 chars).

Feature ids are a shared vocabulary used consistently across the RevEng.AI plugins; reuse
an existing id, or coordinate with the team before introducing a new one.

## Regenerating

```sh
python scripts/emit_features.py          # rewrite .revengai/features.json
python scripts/emit_features.py --check  # exit non-zero if it is stale
```

Standard library only — no Ghidra install or Gradle build required, so the check runs in
plain CI.

## CI

`.github/workflows/features-drift.yml` runs the `--check` on every pull request and fails
if the committed `.revengai/features.json` does not match the script. When you add or
change a feature: update `scripts/emit_features.py`, run the emitter, and commit both.
