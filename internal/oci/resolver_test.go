package oci

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func loadTestFile(t *testing.T, name string) []byte {
	t.Helper()

	path := filepath.Join("testdata", name)
	data, err := os.ReadFile(path)
	require.NoError(t, err)

	return data
}

func TestExporterInfoLayerDigest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		manifest   []byte
		wantDigest string
		wantErr    bool
	}{
		{
			name:       "finds exporter-info layer digest",
			manifest:   loadTestFile(t, "manifest_with_exporter_info_layer.json"),
			wantDigest: "sha256:3333333333333333333333333333333333333333333333333333333333333333",
		},
		{
			name:     "missing exporter-info layer",
			manifest: loadTestFile(t, "manifest_without_exporter_info_layer.json"),
			wantErr:  true,
		},
		{
			name:     "invalid manifest json",
			manifest: []byte("{invalid json"),
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			digest, err := exporterInfoLayerDigest(tt.manifest)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.wantDigest, digest)
		})
	}
}

func TestDecodeExporterInfo(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		blob     []byte
		wantErr  bool
		validate func(t *testing.T, gotCommit string, gotCommitCount int, gotFirstHash string)
	}{
		{
			name: "valid json blob",
			blob: loadTestFile(t, "exporter_info.json"),
			validate: func(t *testing.T, gotCommit string, gotCommitCount int, gotFirstHash string) {
				require.Equal(t, "cptpicard", gotCommit)
				require.Equal(t, 1, gotCommitCount)
				require.Equal(t, "ltdata", gotFirstHash)
			},
		},
		{
			name:    "invalid json blob",
			blob:    []byte("{not json"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := decodeExporterInfo(context.Background(), tt.blob)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, tt.validate)
			require.NotEmpty(t, info.CommitsSinceLastExport)
			tt.validate(t, info.Commit, len(info.CommitsSinceLastExport), info.CommitsSinceLastExport[0].Hash)
		})
	}
}

func TestBuildArtifactReference(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		repository      string
		appliedRevision string
		wantReference   string
		wantErr         bool
	}{
		{
			name:            "accepts digest-pinned revision",
			repository:      "ghcr.io/grafana/kube-manifests",
			appliedRevision: "master@sha256:6971561bf3f0adf0ae0059420b3778302e4c8e44e2ed27bd9acc900b3a7ed45e",
			wantReference:   "ghcr.io/grafana/kube-manifests@sha256:6971561bf3f0adf0ae0059420b3778302e4c8e44e2ed27bd9acc900b3a7ed45e",
		},
		{
			name:            "errors when digest absent",
			repository:      "ghcr.io/grafana/kube-manifests",
			appliedRevision: "master",
			wantErr:         true,
		},
		{
			name:            "errors when digest malformed",
			repository:      "ghcr.io/grafana/kube-manifests",
			appliedRevision: "master@sha256:not-a-real-digest",
			wantErr:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reference, err := buildArtifactReference(tt.repository, tt.appliedRevision)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.wantReference, reference)
		})
	}
}
