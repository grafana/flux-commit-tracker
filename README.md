# `flux-commit-tracker`

## How to run

Run me like this for OTLP:

```console
GITHUB_TOKEN=$(gh auth token) \
  go run \
    github.com/grafana/flux-commit-tracker/cmd/ \
      -kube-context=dev-us-central-0 \
      -telemetry-exporter otlp \
      -telemetry-insecure
```

or this to output to stdout:

```console
GITHUB_TOKEN=$(gh auth token) \
  go run \
    github.com/grafana/flux-commit-tracker/cmd/ \
      -kube-context=dev-us-central-0 \
      -telemetry-exporter otlp \
      -telemetry-insecure
```

This currently outputs all the metrics and tracing too, which is quite noisy.
Grep for `commit info` to see the deltas discovered.

## TODO

- [ ] Add tests
- [ ] Make the output in `stdout` mode sanely readable
- [ ] Verify the telemetry works
- [ ] Make OTLP local dev stuff work properly
- [ ] Switch to Grafana stack in the Docker compose file
