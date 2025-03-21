# `flux-commit-tracker`

## How to run

Run me like this for OTLP:

```console
# Start the Grafana stack
docker-compose up

# In another terminal, or run the above with `-d` to detach
GITHUB_TOKEN=$(gh auth token) \
  go run \
    github.com/grafana/flux-commit-tracker/cmd/ \
      --kube-context=dev-us-central-0 \
      --telemetry-exporter otlp \
      --telemetry-insecure
```

Then take a look at `http://localhost:3000` and look at the metrics/logs/traces
in there.

or this to output to stdout:

```console
GITHUB_TOKEN=$(gh auth token) \
  go run \
    github.com/grafana/flux-commit-tracker/cmd/ \
      --kube-context=dev-us-central-0 \
      --telemetry-exporter stdout \
      --telemetry-insecure
```

This currently outputs all the metrics and tracing too, which is quite noisy.
Grep for `commit info` to see the deltas discovered.

## TODO

- [x] Add more tests
- [ ] Use better log levels (debug) for some messages
- [ ] Make the output in `stdout` mode sanely readable (add a new `stdout-raw`
      mode, make `stdout` mode output only the logs in a human readable format)
- [ ] Add Dockerfile and GitHub action to build and push this
- [ ] Run in dev and push to the `alloy-otlp` environment
- [ ] Set up all the normal repo stuff (branch protection, required reviews, CI,
      Dependabot etc) and make it public
- [x] Verify the telemetry works
- [x] Make OTLP local dev stuff work properly
- [x] Switch to Grafana stack in the Docker compose file
