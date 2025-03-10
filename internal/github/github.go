package github

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptrace"
	"os"
	"time"

	"github.com/go-logr/logr"
	"github.com/google/go-github/v69/github"
	"go.opentelemetry.io/contrib/instrumentation/net/http/httptrace/otelhttptrace"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/oauth2"
)

const (
	OtelName = "github.com/grafana/flux-commit-tracker/internal/github"
)

var (
	tracer = otel.Tracer(OtelName)
)

type GitHubRepo struct {
	Owner string
	Repo  string
}

func (r GitHubRepo) String() string {
	return fmt.Sprintf("%s/%s", r.Owner, r.Repo)
}

type RepositoryNotFoundError struct {
	GitHubRepo
}

func (r RepositoryNotFoundError) Error() string {
	return fmt.Sprintf("repository %s not found. Could it be private? Check your GitHub credentials.", r.GitHubRepo)
}

type CommitInfo struct {
	Hash string
	Time time.Time
}

type GitHub struct {
	logger logr.Logger
	client *github.Client
}

func NewGitHubClient(ctx context.Context, logger logr.Logger, token string) *GitHub {
	tc := &http.Client{
		Transport: otelhttp.NewTransport(
			http.DefaultTransport,
			otelhttp.WithClientTrace(func(ctx context.Context) *httptrace.ClientTrace {
				return otelhttptrace.NewClientTrace(ctx)
			}),
		),
	}
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		ts := oauth2.StaticTokenSource(
			&oauth2.Token{AccessToken: token},
		)

		clientCtx := context.WithValue(ctx, oauth2.HTTPClient, tc)
		tc = oauth2.NewClient(clientCtx, ts)
	}

	return &GitHub{
		logger: logger,
		client: github.NewClient(tc),
	}
}

func (g *GitHub) GetFile(ctx context.Context, repo GitHubRepo, path, ref string) ([]byte, error) {
	ctx, span := tracer.Start(ctx, "github.get_file",
		trace.WithAttributes(
			attribute.String("github.repo", repo.String()),
			attribute.String("github.path", path),
			attribute.String("github.ref", ref),
		))
	defer span.End()

	g.logger.Info("fetching file", "repo", repo, "path", path, "ref", ref)

	content, _, _, err := g.client.Repositories.GetContents(ctx, repo.Owner, repo.Repo, path, &github.RepositoryContentGetOptions{
		Ref: ref,
	})
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to fetch file")

		var ghErr *github.ErrorResponse
		if errors.As(err, &ghErr) && ghErr.Response.StatusCode == http.StatusNotFound {
			return nil, RepositoryNotFoundError{GitHubRepo: repo}
		}

		return nil, fmt.Errorf("fetching file: %w", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(*content.Content)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to decode file content")
		return nil, fmt.Errorf("decoding file: %w", err)
	}

	span.SetAttributes(attribute.Int("github.file.size_bytes", len(decoded)))
	span.SetStatus(codes.Ok, "Successfully fetched and decoded file")
	return decoded, nil
}
