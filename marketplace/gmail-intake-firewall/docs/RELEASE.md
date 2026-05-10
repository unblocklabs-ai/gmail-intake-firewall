# Release

Releases are cut from `main` after `npm run preflight` passes.

## Dry Run

```sh
npm run release -- patch --dry-run
```

## Publish

```sh
npm run release:patch
```

The release script bumps `package.json`, `package-lock.json`, `openclaw.plugin.json`, and `.claude-plugin/marketplace.json`, rebuilds, syncs `marketplace/gmail-intake-firewall`, commits the release metadata, tags `vX.Y.Z`, pushes, publishes npm when enabled by `package.json#openclaw.release.publishToNpm`, and creates a GitHub release.

## Marketplace Mirror

The marketplace package lives at `marketplace/gmail-intake-firewall` and contains only runtime install files. Regenerate it with:

```sh
npm run marketplace:sync
```
