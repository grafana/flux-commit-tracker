package github

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptrace"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/google/go-github/v80/github"
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
	InstrumentationScope = "github"
)

var tracer = otel.Tracer(InstrumentationScope)

// Client defines the interface for interacting with GitHub.
type Client interface {
	GetFile(ctx context.Context, logger *slog.Logger, repo GitHubRepo, path, ref string) ([]byte, error)
	FetchCommitTime(ctx context.Context, log *slog.Logger, repo GitHubRepo, commitSHA string) (time.Time, error)
	FetchExporterInfo(ctx context.Context, log *slog.Logger, repo GitHubRepo, ref string) (ExporterInfo, error)
}

type TokenAuth struct {
	GithubToken string `env:"GITHUB_TOKEN" hidden:"" help:"GitHub personal access token" xor:"token"`
}

// byteSlice is an alias for []byte which parses a string. It's used because
// `kong` expects uints by default
type byteSlice []byte

func (b *byteSlice) UnmarshalText(value []byte) error {
	*b = value
	return nil
}

func (b *byteSlice) String() string {
	return string(*b)
}

type AppAuth struct {
	GithubAppID             int64      `env:"GITHUB_APP_ID" hidden:"" help:"GitHub App ID" and:"app" xor:"token"`
	GithubAppPrivateKey     *byteSlice `env:"GITHUB_APP_PRIVATE_KEY" hidden:"" help:"GitHub App private key" and:"app"`
	GithubAppInstallationID int64      `env:"GITHUB_APP_INSTALLATION_ID" hidden:"" help:"GitHub App installation ID" and:"app"`
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

// gitHubClient is a wrapper around the GitHub client that adds caching, retrying and
// tracing. It implements the Client interface.
type gitHubClient struct {
	client *github.Client
}

// Ensure gitHubClient implements the Client interface.
var _ Client = &gitHubClient{}

// cachingRetryableTracingTransport creates a HTTP RoundTripper that uses a
// retryable HTTP client with caching and tracing capabilities. It uses the
// retryablehttp package to handle retries and the httpcache package to cache
// responses. The tracing is done using the OpenTelemetry library, which allows
// for distributed tracing of HTTP requests. The logger is used to log
// information about the requests and responses.
//
// The function returns a RoundTripper that can be used to make HTTP requests with
// retry, caching, and tracing capabilities.
func cachingRetryableTracingTransport(logger *slog.Logger) http.RoundTripper {
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

func authenticateWithToken(ctx context.Context, logger *slog.Logger, token string) *gitHubClient {
	src := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)

	clientCtx := context.WithValue(ctx, oauth2.HTTPClient, &http.Client{
		Transport: cachingRetryableTracingTransport(logger),
	})
	httpClient := oauth2.NewClient(clientCtx, src)
	githubClient := github.NewClient(httpClient)

	return &gitHubClient{
		client: githubClient,
	}
}

func authenticateWithApp(logger *slog.Logger, appID int64, installationID int64, privateKey []byte) (*gitHubClient, error) {
	itr, err := ghinstallation.New(cachingRetryableTracingTransport(logger), appID, installationID, privateKey)
	if err != nil {
		return &gitHubClient{}, fmt.Errorf("failed to create GitHub App installation transport: %w", err)
	}

	githubClient := github.NewClient(&http.Client{Transport: itr})

	return &gitHubClient{
		client: githubClient,
	}, nil
}

func NewGitHubClient(ctx context.Context, logger *slog.Logger, tokenAuth TokenAuth, appAuth AppAuth) (*gitHubClient, error) {
	// If a GitHub token is provided, use it to authenticate in preference to
	// App authentication
	if tokenAuth.GithubToken != "" {
		logger.DebugContext(ctx, "Using GitHub token for authentication")
		return authenticateWithToken(ctx, logger, tokenAuth.GithubToken), nil
	}

	// Otherwise, use the App authentication flow
	logger.Debug("Using GitHub App for authentication")
	return authenticateWithApp(logger, appAuth.GithubAppID, appAuth.GithubAppInstallationID, *appAuth.GithubAppPrivateKey)
}

func (g *gitHubClient) GetFile(ctx context.Context, logger *slog.Logger, repo GitHubRepo, path, ref string) ([]byte, error) {
	ctx, span := tracer.Start(ctx, "github.get_file",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("github.repo", repo.String()),
			attribute.String("github.path", path),
			attribute.String("github.ref", ref),
		),
	)
	defer span.End()

	logger.DebugContext(ctx, "fetching file", "repo", repo, "path", path, "ref", ref)

	content, _, resp, err := g.client.Repositories.GetContents(ctx, repo.Owner, repo.Repo, path, &github.RepositoryContentGetOptions{
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
	defer func() {
		if err := resp.Body.Close(); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "Failed to close response body")
		}
	}()

	if content == nil || content.Content == nil {
		span.SetStatus(codes.Error, "fetched content or content data is nil")

		return nil, fmt.Errorf("repository GetContents returned nil content for %s/%s path %s @ %s", repo.Owner, repo.Repo, path, ref)
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

// FetchCommitTime fetches the commit time for a given commit SHA in a repository. Returns the commit time in UTC.
func (g *gitHubClient) FetchCommitTime(ctx context.Context, log *slog.Logger, repo GitHubRepo, commitSHA string) (time.Time, error) {
	ctx, span := tracer.Start(ctx, "github.fetch_commit_time",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("github.repo.owner", repo.Owner),
			attribute.String("github.repo.name", repo.Repo),
			attribute.String("github.commit.sha", commitSHA),
		),
	)
	defer span.End()

	log = log.With("repo.owner", repo.Owner, "repo.name", repo.Repo, "commit.sha", commitSHA)
	log.DebugContext(ctx, "fetching commit time from GitHub")

	repoCommit, resp, err := g.client.Repositories.GetCommit(ctx, repo.Owner, repo.Repo, commitSHA, nil)
	if err != nil {
		log.ErrorContext(ctx, "failed to get commit from GitHub", "error", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to get commit")

		return time.Time{}, fmt.Errorf("failed to get commit %s in %s/%s: %w", commitSHA, repo.Owner, repo.Repo, err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "Failed to close response body")
		}
	}()

	if repoCommit.Commit == nil || repoCommit.Commit.Committer == nil || repoCommit.Commit.Committer.Date == nil {
		err := fmt.Errorf("commit or committer date is nil in GitHub response")
		log.ErrorContext(ctx, "invalid commit data received", "error", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, "Invalid commit data")

		return time.Time{}, err
	}

	commitTime := repoCommit.Commit.Committer.GetDate().Time

	span.SetAttributes(attribute.String("github.commit.time", commitTime.UTC().String()))
	span.SetStatus(codes.Ok, "Successfully retrieved commit time")
	log.DebugContext(ctx, "successfully fetched commit time", "commit.time", commitTime.UTC().String())

	return commitTime, nil
}
