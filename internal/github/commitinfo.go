package github

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

type commitInfo struct {
	Hash    string
	Message string
	Author  string
	Email   string
	Time    time.Time
}

type ExporterInfo struct {
	Commit                 string
	CommitsSinceLastExport []*commitInfo `json:"commits_since_last_export"`
	ExportBuildLink        string        `json:"export_build_link"`
}

// FetchExporterInfo fetches and parses the `exporter-info.json` file produced
// by `kube-manifests-exporter` for the given ref.
func (g *GitHub) FetchExporterInfo(ctx context.Context, logger *slog.Logger, kubeManifests GitHubRepo, ref string) (ExporterInfo, error) {
	ctx, span := tracer.Start(ctx, "github.fetch_exporter_info",
		trace.WithAttributes(
			attribute.String("github.repo", kubeManifests.String()),
			attribute.String("github.ref", ref),
			attribute.String("github.file", "exporter-info.json"),
		))
	defer span.End()

	data, err := g.GetFile(ctx, logger, kubeManifests, "exporter-info.json", ref)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to fetch exporter info")
		return ExporterInfo{}, fmt.Errorf("fetching exporter-info: %w", err)
	}

	// Create a subspan for JSON unmarshaling
	var info ExporterInfo
	{
		_, unmarshalSpan := tracer.Start(ctx, "kube_manifests.exporter.info.unmarshal")
		defer unmarshalSpan.End()

		if err := json.Unmarshal(data, &info); err != nil {
			unmarshalSpan.RecordError(err)
			unmarshalSpan.SetStatus(codes.Error, "Failed to parse exporter info")

			span.RecordError(err)
			span.SetStatus(codes.Error, "Failed to parse exporter info")
			return ExporterInfo{}, fmt.Errorf("parsing exporter-info: %w", err)
		}
	}

	span.SetStatus(codes.Ok, "Successfully fetched commit info")
	return info, nil
}
