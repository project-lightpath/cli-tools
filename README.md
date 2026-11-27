# tssc-cli-tools

Supply-chain security tools for the [tssc-validated-pattern][pattern] pipelines,
built as one Go binary in one container image.

[pattern]: https://github.com/project-lightpath/tssc-validated-pattern

## Layout

```
cmd/tssc/            single entrypoint
internal/
  cli/               subcommand wiring, flag surface, env fallbacks
  rhtpa/             SBOM preparation and upload
  tekton/            result files, CA bundle
  version/           build metadata stamped in by the linker
tekton/tasks/        thin Task wrappers that exec the binary
```

The image also installs busybox-style symlinks, so a Task can call
`rhtpa-analyze` instead of `tssc rhtpa analyze`. See
`internal/cli/root.go:argv0Aliases`.

## Conventions

- Every flag also accepts an environment variable (e.g. `--component` /
  `COMPONENT_NAME`); flags win when both are set. The mapping is declared
  per command.
- Tekton results are written to `/tekton/results` when it exists, and
  skipped otherwise.
- Tasks in `tekton/tasks/` map params to flags and nothing else — no
  `script:` blocks.

## Upload SBOMs

Both `upload-sbom-to-rhtpa` and `upload-sbom-to-trustification` use
`tssc rhtpa upload-sbom`. You can also run it locally.

```sh
tssc rhtpa upload-sbom \
  --component my-service \
  --sboms-dir ./sboms \
  --secret-dir ./tpa-secret
```

The Secret directory must contain one file per key: `bombastic_api_url`,
`oidc_issuer_url`, `oidc_client_id`, and `oidc_client_secret`. Use
`--fail-if-not-configured=false` to skip when required keys are missing or
empty. Set `--ca-bundle` for a custom CA outside Tekton. In a TaskRun, the
CLI automatically trusts `/tekton-custom-certs/ca-bundle.crt` if mounted.

Set the optional `supported_cyclonedx_version` key to convert newer files
with Syft. The image bundles Syft 1.19.0. For a local run that needs conversion,
install `syft` on your PATH.

The CLI logs a link per successful upload. It emits the existing
`TPA_SBOM_URL` log marker and Task result for the last SBOM in digest order.
Set `console_url` in the Secret or pass `--console-url` when the console is
on a separate route. Pass the digest of an image containing the command in
the Tasks' `TSSC_CLI_IMAGE` parameter.

## Published image

`quay.io/project-lightpath/tssc-cli-tools`, built for `linux/amd64` and
`linux/arm64`. CI publishes on every merge to `main` and on `v*` tags. Release
tags must use the `vMAJOR.MINOR.PATCH` form, such as `v1.2.3`:

| tag | meaning |
|---|---|
| `sha-<full-commit>-run-<run-id>-<attempt>` | one workflow attempt for a commit; unique across reruns and release events |
| `latest` | newest `main` commit whose serialized promotion passed the freshness check |
| `vX.Y.Z` | release tag for a `vMAJOR.MINOR.PATCH` push |

Pin by digest in a Tekton Task rather than by tag — the digest is printed in
the publish job's summary:

```yaml
image: quay.io/project-lightpath/tssc-cli-tools@sha256:...
```

## Development

```
make            # tidy, vet, test, build
make test       # go test ./... -race
make image      # podman build
```
