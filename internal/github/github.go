package github

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptrace"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/google/go-github/v69/github"
	internallogger "github.com/grafana/flux-commit-tracker/internal/logger"
	"github.com/gregjones/httpcache"
	"github.com/hashicorp/go-retryablehttp"
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

type TokenAuth struct {
	GithubToken string `env:"GITHUB_TOKEN" hidden:"" help:"GitHub personal access token" xor:"token"`
}

type AppAuth struct {
	GithubAppID             int64  `env:"GITHUB_APP_ID" hidden:"" help:"GitHub App ID" and:"app" xor:"token"`
	GithubAppPrivateKey     []byte `env:"GITHUB_APP_PRIVATE_KEY" hidden:"" help:"GitHub App private key" and:"app"`
	GithubAppInstallationID int64  `env:"GITHUB_APP_INSTALLATION_ID" hidden:"" help:"GitHub App installation ID" and:"app"`
}

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
	logger internallogger.Logger
	client *github.Client
}

// cachingRetryableTracingTransport creates a HTTP RoundTripper that uses a
// retryable HTTP client with caching and tracing capabilities. It uses the
// retryablehttp package to handle retries and the httpcache package to cache
// responses. The tracing is done using the OpenTelemetry library, which allows
// for distributed tracing of HTTP requests. The logger is used to log
// information about the requests and responses.
//
// The function returns a RoundTripper that can be used to make HTTP requests with
// retry, caching, and tracing capabilities.
func cachingRetryableTracingTransport(logger internallogger.Logger) http.RoundTripper {
	retryableClient := retryablehttp.NewClient()
	retryableClient.Logger = logger

	tracingCachingTransport := otelhttp.NewTransport(
		retryableClient.HTTPClient.Transport,
		otelhttp.WithClientTrace(func(ctx context.Context) *httptrace.ClientTrace {
			return otelhttptrace.NewClientTrace(ctx)
		}),
	)

	httpCache := httpcache.NewMemoryCacheTransport()
	httpCache.Transport = tracingCachingTransport

	retryableClient.HTTPClient.Transport = httpCache

	return &retryablehttp.RoundTripper{
		Client: retryableClient,
	}
}

func authenticateWithToken(ctx context.Context, logger internallogger.Logger, token string) GitHub {
	src := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)

	clientCtx := context.WithValue(ctx, oauth2.HTTPClient, &http.Client{
		Transport: cachingRetryableTracingTransport(logger),
	})
	httpClient := oauth2.NewClient(clientCtx, src)
	githubClient := github.NewClient(httpClient)

	return GitHub{
		logger: logger,
		client: githubClient,
	}
}

func authenticateWithApp(logger internallogger.Logger, appID int64, installationID int64, privateKey []byte) (GitHub, error) {
	itr, err := ghinstallation.New(cachingRetryableTracingTransport(logger), appID, installationID, privateKey)
	if err != nil {
		return GitHub{}, fmt.Errorf("failed to create GitHub App installation transport: %w", err)
	}

	githubClient := github.NewClient(&http.Client{Transport: itr})

	return GitHub{
		logger: logger,
		client: githubClient,
	}, nil
}

func NewGitHubClient(ctx context.Context, logger internallogger.Logger, tokenAuth TokenAuth, appAuth AppAuth) (GitHub, error) {
	// If a GitHub token is provided, use it to authenticate in preference to
	// App authentication
	if tokenAuth.GithubToken != "" {
		logger.Debug("Using GitHub token for authentication")
		return authenticateWithToken(ctx, logger, tokenAuth.GithubToken), nil
	}

	// Otherwise, use the App authentication flow
	logger.Debug("Using GitHub App for authentication")
	return authenticateWithApp(logger, appAuth.GithubAppID, appAuth.GithubAppInstallationID, []byte(appAuth.GithubAppPrivateKey))
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
