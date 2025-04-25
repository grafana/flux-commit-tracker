# `flux-commit-tracker`

A Kubernetes controller built with `controller-runtime` that tracks the time
taken for commits referenced in Flux Kustomizations
(`kustomize.toolkit.fluxcd.io/v1`) to be applied to the cluster after they were
merged to the source repository. This is used for a Platform SLO which tracks
the speed of our deployment pipeline for Kubernetes changes.

Metrics, logs and traces are exported to an OTLP collector (e.g., the [OpenTelemetry
collector] or [Grafana Alloy]).

[Grafana Alloy]: https://grafana.com/docs/alloy/latest/
[OpenTelemetry collector]: https://opentelemetry.io/docs/collector/

## How does it work?

Although this repository is open source, it tracks changes made through a
process that is not yet. Here's a brief description of the process so you can
understand what we're measuring here.

1. Engineers make changes to Jsonnet code in a repository
   `grafana/deployment_tools`. This is our infrastructure-as-code monorepo. The
   Jsonnet code describes [Tanka] environments.
2. Pull requests get created and reviewed as normal.
3. Once merged, a program called `kube-manifests-exporter` runs on the `master`
   branch. Only one of these runs can be in progress at a time, to prevent out
   of order deploys. A run finds all the commits that happened since the last
   run (which didn't get them due to this locking) and runs `tk export` on all
   the modified environments. The `tk tool importers` subcommand is used to
   determine this in the case of library changes.
4. If there are any changes, a commit to `kube-manifests` with the
   updated Kubernetes YAMLs produced by `tk export` is made and pushed. Grafana
   Cloud is made up of several clusters, and the YAMLs end up in a directory
   corresponding to their cluster. Alongside this, a file `exporter-info.json`
   is updated to contain details about the commits which were exported in this
   run.
5. [Flux], running in each cluster and watching the `kube-manifests` repository,
   detects the change. Each cluster's flux is configured to watch for changes in
   its own directory. It looks at the commit to determine if it needs to do
   anything, and acts accordingly.

When Flux finds a new commit in `kube-manifests`, it updates the
`status.lastAppliedRevision` of its `Kustomization` objects. This creates an
event in the cluster which we hook into here. We can see the commits as Flux
sees them, then go off and fetch the `exporter-info.json` file, and calculate
the times which we need.

## Metrics exported

- `flux_commit_tracker.kube-manifests-exporter.export-time`: The time taken
  for the exporter to export the changes to `kube-manifests` and push them.
- `flux_commit_tracker.flux.reconcile-time`: The time taken for Flux to
  notice the commit and apply it to the cluster.
- `flux_commit_tracker.e2e.export-time`: The time taken for the
  exporter to export the changes to `kube-manifests` and push them, plus the
  time taken for Flux to notice the commit and apply it to the cluster (the
  total of the above metrics).

[Flux]: https://fluxcd.io/
[Tanka]: https://tanka.dev/

## How to run

There are two main ways to run `flux-commit-tracker`:

### Locally, talking to a remote cluster

- You need access to a Kubernetes cluster configuration (e.g., via
  `~/.kube/config`).
- Specify the Kubernetes context to use with the `--kube-context` flag.
  If omitted, we will use the default context.
- Ensure you have a Grafana observability stack running for OTLP export.

  You can use the provided `docker-compose.yml`:

  ```bash
  # Start the Grafana stack
  docker-compose up -d
  ```

  The default OTLP endpoint will write here. Visit
  <http://localhost:3000/explore> to see the exported metrics, logs and traces.

### In-Cluster

- Deploy the controller within your Kubernetes cluster (e.g., using a
  Deployment).
- It will automatically use the service account token mounted into the pod
  for Kubernetes API access. Do _not_ provide `--kube-context`.
- Ensure network connectivity to your OTLP collector endpoint if using OTLP.

## Configuration

You need to provide GitHub credentials either via a Personal Access Token or a
GitHub App configuration.

Configuration can be provided via command-line flags or environment variables:

| Flag                   | Environment Variable         | Description                        |
| ---------------------- | ---------------------------- | ---------------------------------- |
| `--health-addr`        | `HEALTH_ADDR`                | Health addr (def: `:9440`)         |
| `--kube-context`       | `KUBE_CONTEXT`               | K8s context (when running locally) |
| `--log-level`          | `LOG_LEVEL`                  | Log level (e.g., `info`)           |
| `--metrics-addr`       | `METRICS_ADDR`               | Metrics addr (def: `:8888`)        |
| `--telemetry-endpoint` | `TELEMETRY_ENDPOINT`         | OTLP endpoint (host:port)          |
| `--telemetry-insecure` | `TELEMETRY_INSECURE`         | Use insecure OTLP conn             |
| `--telemetry-mode`     | `TELEMETRY_MODE`             | Telemetry mode                     |
| _(N/A)_                | `GITHUB_TOKEN`               | GitHub PAT                         |
| _(N/A)_                | `GITHUB_APP_ID`              | GitHub App ID                      |
| _(N/A)_                | `GITHUB_APP_PRIVATE_KEY`     | GitHub App Private Key             |
| _(N/A)_                | `GITHUB_APP_INSTALLATION_ID` | GitHub App Install ID              |

The controller supports several telemetry modes via the `--telemetry-mode`
flag / `TELEMETRY_MODE` env var. This determines whether telemetry is printed to
standard output or exported via OTLP.

- `otlp`: Sends telemetry (logs, traces, metrics) to an OTLP collector (default
  endpoint: `localhost:4317`, configure via `--telemetry-endpoint` /
  `TELEMETRY_ENDPOINT`).
- `stdout-logs`: Outputs only application logs to the console.
- `stdout-logs+otlp`: Sends to OTLP _and_ outputs logs to the console.

_The `-all` variants are very verbose because the traces and metrics contain a
lot of data._

- `stdout-all`: Outputs all telemetry to the console (can be noisy).
- `stdout-all+otlp`: Sends to OTLP _and_ outputs all telemetry to console.

**Example (running locally, OTLP mode, GitHub Token):**

This example reuses the `gh` CLI's GitHub token.

```console
GITHUB_TOKEN=$(gh auth token) \
go run \
  github.com/grafana/flux-commit-tracker/cmd/ \
    --kube-context=dev-us-central-0 \
    --telemetry-mode otlp
```

If using OTLP, examine telemetry in Grafana (e.g., `http://localhost:3000`
with the default Docker Compose setup).

Remember to use the appropriate auth method (Token/App) and K8s config
method (flag/in-cluster). See `--help` for all options.

### Running from a Docker image

We push a Docker image to the GitHub Container Registry:

```bash
docker run --rm \
  -e GITHUB_TOKEN=$(gh auth token) \
  ghcr.io/grafana/flux-commit-tracker:latest \
  --log-level=debug
```

Semver-tagged images will be available for any releases once we have them, as is
`main` for the latest commit on the `main` branch.

These docker images are attested using [GitHub Artifact Attestations][attest].
You can verify our container images by using the `gh` CLI:

```console
$ gh attestation verify --repo grafana/flux-commit-tracker oci://ghcr.io/grafana/flux-commit-tracker:<tag>
Loaded digest sha256:... for oci://ghcr.io/grafana/flux-commit-tracker:<sometag>
Loaded 3 attestations from GitHub API
✓ Verification succeeded!

sha256:<sometag> was attested by:
REPO                                PREDICATE_TYPE                  WORKFLOW
grafana/flux-commit-tracker         https://slsa.dev/provenance/v1  .github/workflows/build.yml@<somref>
```

Attestations can also be viewed on the [attestation page] of this repository.

What this lets you do is trace a container image back to a build in this
repository. You'll still need to verify the build steps that were used to build
the image to ensure that the image is safe to use.

[attest]: https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds
[attestation page]: https://github.com/grafana/flux-commit-tracker/attestations
