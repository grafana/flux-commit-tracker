package oci

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"go.opentelemetry.io/contrib/instrumentation/net/http/httptrace/otelhttptrace"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

type remoteRegistryClient struct {
	transport http.RoundTripper
}

// tracingTransport returns an HTTP transport with OpenTelemetry client
// instrumentation for outbound OCI registry requests.
func tracingTransport() http.RoundTripper {
	return otelhttp.NewTransport(
		http.DefaultTransport,
		otelhttp.WithClientTrace(func(ctx context.Context) *httptrace.ClientTrace {
			return otelhttptrace.NewClientTrace(ctx)
		}),
	)
}

func (c *remoteRegistryClient) GetManifest(ctx context.Context, reference string) ([]byte, error) {
	ctx, span := tracer.Start(ctx, "oci.get_manifest",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(attribute.String("oci.reference", reference)),
	)
	defer span.End()

	ref, err := name.ParseReference(reference)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to parse OCI reference")
		return nil, fmt.Errorf("parsing OCI reference: %w", err)
	}

	desc, err := remote.Get(
		ref,
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithTransport(c.transport),
	)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to fetch OCI descriptor")
		return nil, err
	}

	manifest, err := desc.RawManifest()
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to read raw manifest")
		return nil, err
	}

	span.SetAttributes(attribute.Int("oci.manifest.bytes", len(manifest)))
	span.SetStatus(codes.Ok, "Successfully fetched OCI manifest")
	return manifest, nil
}

func (c *remoteRegistryClient) GetLayerBlob(ctx context.Context, reference string) ([]byte, error) {
	ctx, span := tracer.Start(ctx, "oci.get_layer_blob",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(attribute.String("oci.layer.reference", reference)),
	)
	defer span.End()

	ref, err := name.NewDigest(reference)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to parse layer reference")
		return nil, fmt.Errorf("parsing OCI layer reference: %w", err)
	}

	layer, err := remote.Layer(
		ref,
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithTransport(c.transport),
	)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to fetch layer")
		return nil, err
	}

	reader, err := layer.Compressed()
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to open compressed layer stream")
		return nil, fmt.Errorf("reading OCI layer stream: %w", err)
	}
	defer func() { _ = reader.Close() }()

	data, err := io.ReadAll(reader)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to read layer bytes")
		return nil, fmt.Errorf("reading OCI layer bytes: %w", err)
	}

	span.SetAttributes(attribute.Int("oci.layer.bytes", len(data)))
	span.SetStatus(codes.Ok, "Successfully fetched layer blob")
	return data, nil
}
