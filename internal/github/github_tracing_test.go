package github

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/go-github/v82/github"
	"github.com/grafana/flux-commit-tracker/internal/otel"
	"github.com/migueleliasweb/go-github-mock/src/mock"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

var testTel *otel.TestTelemetry

func TestMain(m *testing.M) {
	ctx := context.Background()

	// Set up the OpenTelemetry SDK with a test exporter. Do this globally as otel
	// installs its handlers globally and doing this twice doens't work well.
	var err error
	testTel, err = otel.SetupTestTelemetry(ctx, "github_test")
	if err != nil {
		panic(err)
	}

	// Run the tests
	m.Run()
}

func TestTraceInstrumentation(t *testing.T) {
	ctx := t.Context()

	t.Cleanup(testTel.Clear)

	ctx, span := testTel.Tracer.Start(ctx, "test_parent_span")

	mockedHTTPClient := mock.NewMockedHTTPClient(
		mock.WithRequestMatch(
			mock.GetReposContentsByOwnerByRepoByPath,
			&github.RepositoryContent{
				Content: github.Ptr(content),
			},
		),
	)

	ghClient := newClientFromMock(t, mockedHTTPClient)

	repo := GitHubRepo{
		Owner: "owner",
		Repo:  "repo",
	}
	path := "path/to/file"
	ref := "main"

	_, err := ghClient.GetFile(ctx, logger, repo, path, ref)
	require.NoError(t, err)

	span.End()

	getFileSpan := testTel.FindSpan(t, ctx, "github.get_file")
	require.NotNil(t, getFileSpan, "Could not find the 'github.get_file' span")

	expectedAttrs := []attribute.KeyValue{
		attribute.String("github.repo", repo.String()),
		attribute.String("github.path", path),
		attribute.String("github.ref", ref),
		attribute.Int("github.file.size_bytes", len([]byte("hello world"))),
	}

	otel.AssertSpanAttributes(t, getFileSpan, expectedAttrs)

	otel.AssertSpanStatus(t, getFileSpan, codes.Ok)
}

func TestTraceInstrumentationWithError(t *testing.T) {
	ctx := t.Context()

	t.Cleanup(testTel.Clear)

	ctx, span := testTel.Tracer.Start(ctx, "test_parent_span")

	ghClient := newErrorReturningClient(t, mock.GetReposContentsByOwnerByRepoByPath, http.StatusNotFound)

	repo := GitHubRepo{
		Owner: "not-found",
		Repo:  "repo",
	}

	_, err := ghClient.GetFile(ctx, logger, repo, "path", "ref")
	require.Error(t, err)

	span.End()

	repoNotFoundError := RepositoryNotFoundError{}
	require.ErrorAs(t, err, &repoNotFoundError)

	getFileSpan := testTel.FindSpan(t, ctx, "github.get_file")
	require.NotNil(t, getFileSpan, "Could not find the 'github.get_file' span")

	otel.AssertSpanStatus(t, getFileSpan, codes.Error)

	// Verify error event was recorded
	require.Condition(t, func() bool {
		for _, event := range getFileSpan.Events() {
			if event.Name == "exception" {
				return true
			}
		}
		return false
	})
}
