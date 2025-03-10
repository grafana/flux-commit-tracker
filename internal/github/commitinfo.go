package github

import (
	"context"
	"encoding/json"
	"fmt"
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

func (g *GitHub) FetchCommitInfo(ctx context.Context, kubeManifests GitHubRepo, ref string) (ExporterInfo, error) {
	ctx, span := tracer.Start(ctx, "github.fetch_commit_info",
		trace.WithAttributes(
			attribute.String("github.repo", kubeManifests.String()),
			attribute.String("github.ref", ref),
			attribute.String("github.file", "exporter-info.json"),
		))
	defer span.End()

	data, err := g.GetFile(ctx, kubeManifests, "exporter-info.json", ref)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to fetch exporter info")
		return ExporterInfo{}, fmt.Errorf("fetching exporter-info: %w", err)
	}

	// Create a subspan for JSON unmarshaling
	var info ExporterInfo
	{
		_, unmarshalSpan := tracer.Start(ctx, "github.unmarshal_exporter_info")
		defer unmarshalSpan.End()
		if err := json.Unmarshal(data, &info); err != nil {
			unmarshalSpan.RecordError(err)
			unmarshalSpan.SetStatus(codes.Error, "Failed to parse exporter info")

			span.RecordError(err)
			span.SetStatus(codes.Error, "Failed to parse exporter info")
			return ExporterInfo{}, fmt.Errorf("parsing exporter-info: %w", err)
		}
	}

	if len(info.CommitsSinceLastExport) > 0 {
		span.SetAttributes(attribute.Int("github.commits_count", len(info.CommitsSinceLastExport)))
	}

	span.SetStatus(codes.Ok, "Successfully fetched commit info")
	return info, nil
}
