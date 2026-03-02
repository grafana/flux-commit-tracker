package oci

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	otel "go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const ExporterInfoLayerMediaType = "application/vnd.grafana.exporter-info.v1+json"
const InstrumentationScope = "oci"

var digestPattern = regexp.MustCompile(`^sha256:[a-fA-F0-9]{64}$`)
var tracer = otel.Tracer(InstrumentationScope)

type Resolver interface {
	FetchExporterInfo(ctx context.Context, log *slog.Logger, repositoryURL, appliedRevision string) (ExporterInfo, error)
}

type registryClient interface {
	GetManifest(ctx context.Context, reference string) ([]byte, error)
	GetLayerBlob(ctx context.Context, reference string) ([]byte, error)
}

type resolver struct {
	registry registryClient
}

func NewResolver() Resolver {
	return &resolver{
		registry: &remoteRegistryClient{
			transport: tracingTransport(),
		},
	}
}

func (c *resolver) FetchExporterInfo(ctx context.Context, log *slog.Logger, repositoryURL, appliedRevision string) (ExporterInfo, error) {
	ctx, span := tracer.Start(ctx, "oci.fetch_exporter_info",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("oci.repository_url", repositoryURL),
			attribute.String("oci.applied_revision", appliedRevision),
		),
	)
	defer span.End()

	repository := strings.TrimPrefix(repositoryURL, "oci://")

	artifactRef, err := buildArtifactReference(repository, appliedRevision)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to build artifact reference")
		return ExporterInfo{}, fmt.Errorf("building OCI artifact reference: %w", err)
	}
	span.SetAttributes(attribute.String("oci.artifact.reference", artifactRef))

	log.DebugContext(ctx, "fetching OCI manifest", "oci.reference", artifactRef)

	manifestBytes, err := c.registry.GetManifest(ctx, artifactRef)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to fetch manifest")
		return ExporterInfo{}, fmt.Errorf("fetching OCI manifest %q: %w", artifactRef, err)
	}

	layerDigest, err := exporterInfoLayerDigest(manifestBytes)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to locate exporter-info layer")
		return ExporterInfo{}, err
	}
	span.SetAttributes(attribute.String("oci.exporter_info.layer_digest", layerDigest))

	layerRef := repository + "@" + layerDigest
	log.DebugContext(ctx, "fetching exporter-info OCI layer", "oci.layer.reference", layerRef)

	layerBlob, err := c.registry.GetLayerBlob(ctx, layerRef)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to fetch exporter-info layer")
		return ExporterInfo{}, fmt.Errorf("fetching exporter-info OCI layer %q: %w", layerRef, err)
	}

	info, err := decodeExporterInfo(ctx, layerBlob)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to decode exporter-info")
		return ExporterInfo{}, fmt.Errorf("decoding exporter-info OCI layer: %w", err)
	}
	span.SetAttributes(attribute.Int("kube_manifests.exporter.info.commits_exported", len(info.CommitsSinceLastExport)))
	span.SetStatus(codes.Ok, "Successfully fetched exporter-info from OCI")

	return info, nil
}

// buildArtifactReference converts Flux Kustomization status.lastAppliedRevision
// into a digest-pinned OCI reference.
//
// For OCI sources in our clusters, Flux reports revisions as
// "<tag>@sha256:<64hex>" (e.g., "master@sha256:...").
func buildArtifactReference(repository, appliedRevision string) (string, error) {
	tag, digest, ok := strings.Cut(appliedRevision, "@")
	if !ok || tag == "" || !digestPattern.MatchString(digest) {
		return "", fmt.Errorf("applied revision %q is not in expected format <tag>@sha256:<64hex>", appliedRevision)
	}

	return repository + "@" + digest, nil
}

func exporterInfoLayerDigest(manifestBytes []byte) (string, error) {
	var manifest struct {
		Layers []struct {
			MediaType string `json:"mediaType"`
			Digest    string `json:"digest"`
		} `json:"layers"`
	}

	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return "", fmt.Errorf("invalid OCI manifest JSON: %w", err)
	}

	for _, layer := range manifest.Layers {
		if layer.MediaType == ExporterInfoLayerMediaType {
			return layer.Digest, nil
		}
	}

	return "", errors.New("exporter-info OCI layer not found")
}

func decodeExporterInfo(ctx context.Context, layerBlob []byte) (ExporterInfo, error) {
	_, span := tracer.Start(ctx, "oci.decode_exporter_info")
	defer span.End()

	var info ExporterInfo

	if err := json.Unmarshal(layerBlob, &info); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to decode exporter-info JSON")
		return ExporterInfo{}, fmt.Errorf("layer is not valid JSON: %w", err)
	}

	span.SetAttributes(
		attribute.String("repo.kube_manifests.hash", info.Commit),
		attribute.Int("kube_manifests.exporter.info.commits_exported", len(info.CommitsSinceLastExport)),
	)
	span.SetStatus(codes.Ok, "Successfully decoded exporter-info JSON")
	return info, nil
}
