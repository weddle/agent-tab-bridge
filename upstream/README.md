# OpenClaw filtered upstream

Development uses a separate, generated, history-filtered mirror of selected paths from `https://github.com/openclaw/openclaw`. The mirror is not required to build or run Agent Tab Bridge, is not a GitHub-native fork, and must not contain hand-authored commits.

## Current import

- OpenClaw source commit: `b907309b35754e25aa15a309ce6cf63875267c71`
- Filtered mirror commit: `734cb551c970599fefc775c609edb745bb3b10dc`
- Mirror tag: `openclaw-b907309b35754e25aa15a309ce6cf63875267c71`
- `git-filter-repo` revision: `a40bce548d2c`
- Filter manifest: `openclaw-paths.txt`

The source SHA is the authoritative provenance identifier. Filtered commit IDs exist only in the generated mirror.

## Refreshing the mirror

Regenerate from a disposable, `--single-branch --no-tags` clone using the exact path manifest and filter implementation recorded above. Create an annotated `openclaw-<full-source-sha>` tag after filtering. A normal fast-forward update is expected when the filter remains stable; a rejected non-fast-forward push or fetch is a stop condition, not a reason to force-rewrite the mirror.

Updates enter this project through a reviewed merge from the local `openclaw` remote. OpenClaw-specific branding, gateway, copilot/sidebar, page-sharing, telemetry, and unrelated runtime changes must not be reintroduced.
