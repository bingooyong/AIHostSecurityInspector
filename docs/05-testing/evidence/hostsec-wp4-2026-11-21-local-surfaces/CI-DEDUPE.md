# CI trigger and concurrency (this PR)

File: `.github/workflows/ci.yml`

## Triggers

- `push` only on `main`
- `pull_request` types: `opened`, `synchronize`, `reopened`
- No `review`, `comment`, or `label` triggers

## Concurrency

```yaml
concurrency:
  group: ${{ github.workflow }}-${{ github.event.pull_request.number || github.ref }}
  cancel-in-progress: true
```

Same PR number shares one group, so Cloud Agent / successive `synchronize` pushes cancel the in-progress run instead of stacking. Feature-branch `push` no longer duplicates `pull_request`. Default-branch `push` still uses `github.ref`.

This does not skip tests, change billing settings, or mark a billing-blocked remote run as PASS.
