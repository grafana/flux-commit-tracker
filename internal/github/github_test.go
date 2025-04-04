package github

import (
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/google/go-github/v69/github"
	"github.com/gregjones/httpcache"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/migueleliasweb/go-github-mock/src/mock"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"golang.org/x/oauth2"
)

var (
	logger = slog.New(slog.DiscardHandler)

	content = "aGVsbG8gd29ybGQ=" // base64 encoded "hello world"
)

// TestNewGitHubClientWithToken tests that NewGitHubClient returns a client
// whose transport is correctly configured to use the provided token and which
// has a stack of transports:
// - retryable
// - caching
// - tracing
func TestNewGitHubClientWithToken(t *testing.T) {
	t.Parallel()

	tokenAuth := TokenAuth{
		GithubToken: "my-token",
	}

	githubClient, err := NewGitHubClient(t.Context(), logger, tokenAuth, AppAuth{})
	require.NoError(t, err)

	if githubClient.client == nil {
		t.Fatal("Returned client has nil Client field")
	}

	transport, ok := githubClient.client.Client().Transport.(*oauth2.Transport)
	require.Truef(t, ok, "Returned client transport is not an oauth2 transport (is %T)", githubClient.client.Client().Transport)

	token, err := transport.Source.Token()
	require.NoErrorf(t, err, "Returned client transport has no token: %s", err)
	require.Equalf(t, tokenAuth.GithubToken, token.AccessToken, "Returned client transport has incorrect token (is %s)", token.AccessToken)

	retryableTransport, ok := transport.Base.(*retryablehttp.RoundTripper)
	require.Truef(t, ok, "Returned client transport is not a retryable transport (is %T)", transport.Base)

	cacheTransport, ok := retryableTransport.Client.HTTPClient.Transport.(*httpcache.Transport)
	require.Truef(t, ok, "Returned client transport is not a caching transport (is %T)", retryableTransport.Client.HTTPClient.Transport)

	require.IsTypef(t, &otelhttp.Transport{}, cacheTransport.Transport, "Returned client transport is not an otelhttp tracing transport (is %T)", retryableTransport.Client.HTTPClient.Transport)
}

// TestNewGitHubClientWithAppAuthentication tests that NewGitHubClient returns a
// client whose transport is correctly configured to use the provided app
// authentication and uses a retrying transport which itself uses a caching
// transport.
func TestNewGitHubClientWithAppAuthentication(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	// Set up test data
	appAuth := AppAuth{
		GithubAppInstallationID: 123,
		GithubAppID:             456,
		// generate this with: openssl genrsa 32 2>/dev/null | awk 1 ORS='\\n'
		GithubAppPrivateKey: []byte("-----BEGIN RSA PRIVATE KEY-----\nMC0CAQACBQD7J5Q9AgMBAAECBB6C8NkCAwD+JwIDAPz7AgMA1xcCAkoZAgMAwE8=\n-----END RSA PRIVATE KEY-----"),
	}

	githubClient, err := NewGitHubClient(ctx, logger, TokenAuth{}, appAuth)
	require.NoError(t, err)

	if githubClient.client == nil {
		t.Fatal("Returned client has nil Client field")
	}

	transport, ok := githubClient.client.Client().Transport.(*ghinstallation.Transport)
	require.Truef(t, ok, "Returned client transport is not a ghinstallation AppsTransport (is %T)", githubClient.client.Client().Transport)

	innerTransport, ok := transport.Client.(*http.Client)
	require.Truef(t, ok, "Returned client transport is not a http.Client (is %T)", transport.Client)

	nestedTransport, ok := innerTransport.Transport.(*retryablehttp.RoundTripper)
	require.Truef(t, ok, "Returned client transport is not a retryable transport (is %T)", nestedTransport)

	require.IsTypef(t, &httpcache.Transport{}, nestedTransport.Client.HTTPClient.Transport, "Returned client transport is not a caching transport (is %T)", nestedTransport.Client.HTTPClient.Transport)
}

// newClientFromMock returns a new GHClient whose transport is configured to use
// the provided mockClient.
func newClientFromMock(t *testing.T, mockClient *http.Client) GitHub {
	t.Helper()

	// descend through the layers of transports to the bottom-most one, which is
	// the caching transport. replace its underlying transport with the mock one
	transport := cachingRetryableTracingTransport(logger).(*retryablehttp.RoundTripper)
	cachingTransport := transport.Client.HTTPClient.Transport.(*httpcache.Transport)
	cachingTransport.Transport = mockClient.Transport

	// set a really short timeout so that the tests don't take forever
	transport.Client.RetryWaitMax = 1 * time.Millisecond

	httpClient := &http.Client{Transport: transport}

	return GitHub{
		client: github.NewClient(httpClient),
	}
}

// TestResponsesAreRetried tests that responses are retried by the retrying
// transport which underlies the github clients we create.
func TestResponsesAreRetried(t *testing.T) {
	t.Parallel()

	retryCount := 0
	mockClient := mock.NewMockedHTTPClient(
		mock.WithRequestMatchHandler(
			mock.GetReposPullsByOwnerByRepoByPullNumber,
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				retryCount++
				mock.WriteError(
					w,
					http.StatusInternalServerError,
					"Internal Server Error",
				)
			}),
		),
	)

	ghclient := newClientFromMock(t, mockClient)
	_, _, err := ghclient.client.PullRequests.Get(t.Context(), "owner", "repo", 1)

	require.Error(t, err)
	require.Equal(t, 5, retryCount)
}

// TestResponsesAreCached tests that responses are cached by the caching
// transport which underlies the github clients we create.
func TestResponsesAreCached(t *testing.T) {
	t.Parallel()

	hits := 0
	lastStatusSent := 0

	repo := GitHubRepo{
		Owner: "owner",
		Repo:  "repo",
	}

	mockClient := mock.NewMockedHTTPClient(
		mock.WithRequestMatchHandler(
			mock.GetReposContentsByOwnerByRepoByPath,
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits++

				// check if we got an If-Modified-Since header with the value of now
				if ims := r.Header.Get("If-Modified-Since"); ims != "" {
					lastStatusSent = http.StatusNotModified
					w.WriteHeader(lastStatusSent)
					return
				}

				// write cache-control headers to ensure that the response is cached
				w.Header().Set("Cache-Control", "max-age=1, must-revalidate")
				// and Last-Modified to ensure that the response is not considered stale
				w.Header().Set("Last-Modified", time.Now().Format(http.TimeFormat))

				lastStatusSent = http.StatusOK
				w.WriteHeader(lastStatusSent)

				contents := &github.RepositoryContent{
					Content: github.Ptr(content),
				}

				_, err := w.Write(mock.MustMarshal(contents))
				require.NoError(t, err)
			}),
		),
	)

	ghclient := newClientFromMock(t, mockClient)

	returnedContent, err := ghclient.GetFile(t.Context(), logger, repo, "path/to/file", "README.md")
	require.NoError(t, err)
	require.Equal(t, 1, hits)
	require.Equal(t, http.StatusOK, lastStatusSent)
	require.Equal(t, []byte("hello world"), returnedContent)

	// this one should be cached, so the mockClient should not be hit
	returnedContent2, err := ghclient.GetFile(t.Context(), logger, repo, "path/to/file", "README.md")
	require.NoError(t, err)
	require.Equal(t, 1, hits)
	require.Equal(t, returnedContent, returnedContent2)

	// wait for the cache to expire
	time.Sleep(1 * time.Second)

	// the cache has expired, so the mockClient should be hit again, but this
	// time with an If-Modified-Since header which should cause the server to
	// return a 304 Not Modified response
	returnedContent3, err := ghclient.GetFile(t.Context(), logger, repo, "path/to/file", "README.md")
	require.NoError(t, err)
	require.Equal(t, 2, hits)
	require.Equal(t, http.StatusNotModified, lastStatusSent)
	require.Equal(t, returnedContent, returnedContent3)
}

func errorReturningHandler(t *testing.T, m mock.EndpointPattern, code int) mock.MockBackendOption {
	t.Helper()

	return mock.WithRequestMatchHandler(
		m,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mock.WriteError(
				w,
				code,
				http.StatusText(code),
			)
		}),
	)
}

func newErrorReturningClient(t *testing.T, m mock.EndpointPattern, code int) GitHub {
	t.Helper()

	return newClientFromMock(t, mock.NewMockedHTTPClient(
		errorReturningHandler(t, m, code),
	))
}

func TestGetFile_Success(t *testing.T) {
	t.Parallel()

	mockedHTTPClient := mock.NewMockedHTTPClient(
		mock.WithRequestMatch(
			mock.GetReposContentsByOwnerByRepoByPath,
			&github.RepositoryContent{
				Content: github.Ptr(content),
			},
		),
	)

	ghClient := newClientFromMock(t, mockedHTTPClient)
	returnedContent, err := ghClient.GetFile(t.Context(), logger, GitHubRepo{
		Owner: "owner",
		Repo:  "repo",
	}, "path/to/file", "README.md")

	require.NoError(t, err)
	require.Equal(t, []byte("hello world"), returnedContent)
}

func TestGetFile(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		path        string
		ref         string
		setupMock   func(t *testing.T) GitHub
		want        []byte
		wantErr     bool
		expectedErr error
	}{
		{
			name: "get file success",
			path: "path/to/file",
			ref:  "main",
			setupMock: func(t *testing.T) GitHub {
				t.Helper()
				return newClientFromMock(t, mock.NewMockedHTTPClient(
					mock.WithRequestMatch(
						mock.GetReposContentsByOwnerByRepoByPath,
						github.RepositoryContent{
							Content: github.Ptr("aGV5IHRoZXJl"),
						},
					),
				))
			},
			want: []byte("hey there"),
		},
		{
			name: "get file error",
			path: "nonexistent",
			ref:  "main",
			setupMock: func(t *testing.T) GitHub {
				t.Helper()

				return newErrorReturningClient(t, mock.GetReposContentsByOwnerByRepoByPath, http.StatusInternalServerError)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			client := tt.setupMock(t)

			got, err := client.GetFile(ctx, logger, GitHubRepo{Owner: "owner", Repo: "repo"}, tt.path, tt.ref)
			if tt.wantErr {
				require.Error(t, err)
				if tt.expectedErr != nil {
					require.ErrorIs(t, err, tt.expectedErr)
				}
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
