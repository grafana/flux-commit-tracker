package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/alecthomas/kong"
	kustomizev1 "github.com/fluxcd/kustomize-controller/api/v1"
	kustomizev1beta2 "github.com/fluxcd/kustomize-controller/api/v1beta2"
	"github.com/go-logr/logr"
	"github.com/grafana/flux-commit-tracker/internal/github"
	internallogger "github.com/grafana/flux-commit-tracker/internal/logger"
	internalotel "github.com/grafana/flux-commit-tracker/internal/otel"
	"github.com/grafana/flux-commit-tracker/internal/tracker"
	"github.com/lmittmann/tint"
	"github.com/mattn/go-isatty"
	otelruntime "go.opentelemetry.io/contrib/instrumentation/runtime"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

const (
	// FallbackNamespace is the namespace to look for a Kustomization in if the
	// runtime namespace is not available.
	FallbackNamespace = "default"
)

// k8s controller
var scheme = runtime.NewScheme()

func init() {
	// k8s controller initialisation
	_ = clientgoscheme.AddToScheme(scheme)
	_ = kustomizev1.AddToScheme(scheme)
	_ = kustomizev1beta2.AddToScheme(scheme)
}

// ControllerConfig holds configuration for the controller
type ControllerConfig struct {
	KubeContext string `help:"The name of the kubeconfig context to use." default:"" env:"KUBE_CONTEXT"`
	MetricsAddr string `help:"The address the metric endpoint binds to." default:":8888" env:"METRICS_ADDR"`
	HealthAddr  string `help:"The address the health endpoint binds to." default:":9440" env:"HEALTH_ADDR"`
}

// TelemetryConfig holds configuration for the OpenTelemetry exporters
type TelemetryConfig struct {
	// TelemetryMode determines how telemetry signals (logs, traces, metrics) are handled.
	Mode internalotel.TelemetryMode `help:"Telemetry mode (stdout-logs, stdout-all, stdout-logs+otlp, stdout-all+otlp, otlp)" enum:"stdout-logs,stdout-all,stdout-logs+otlp,stdout-all+otlp,otlp" env:"TELEMETRY_MODE" required:""`
	// OTLP Endpoint (used only if mode includes '+otlp')
	Endpoint string `help:"The endpoint of the OTLP collector (host:port)." default:"localhost:4317" env:"TELEMETRY_ENDPOINT"`
	// OTLP Insecure (used only if mode includes '+otlp')
	Insecure bool `help:"Whether to use insecure connection for OTLP telemetry." default:"true" env:"TELEMETRY_INSECURE"`
}

// CLI represents the command-line interface options: the controller config plus
// GitHub auth credentials
type CLI struct {
	Config    ControllerConfig `embed:""`
	Telemetry TelemetryConfig  `embed:"" prefix:"telemetry-"`

	// The enum is in capitals, but any casing will work. `slog.Level`'s
	// `UnmarshalText` method is case-insensitive.
	LogLevel slog.Level `help:"Log level (trace, debug, info, warn, error)" enum:"TRACE,DEBUG,INFO,WARN,ERROR" env:"LOG_LEVEL" default:"INFO"`

	Token github.TokenAuth `embed:""`
	App   github.AppAuth   `embed:""`
}

func (c CLI) Validate(kctx *kong.Context) error {
	if c.Token.GithubToken == "" && c.App.GithubAppID == 0 {
		return fmt.Errorf("either GITHUB_TOKEN or GITHUB_APP_ID, GITHUB_APP_PRIVATE_KEY and GITHUB_APP_INSTALLATION_ID must be set")
	}

	return nil
}

func main() {
	var cli CLI

	parser, err := kong.New(&cli,
		kong.Name("flux-coammit-tracker"),
		kong.Description("Kubernetes controller that tracks the time taken from commit to flux apply."),
		kong.UsageOnError(),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating parser: %v\n", err)
		os.Exit(1)
	}

	kCtx, err := parser.Parse(os.Args[1:])
	parser.FatalIfErrorf(err)

	stdoutHandler := slog.DiscardHandler
	if cli.Telemetry.Mode.IncludesStdoutLogs() {
		// If we're on a TTY, we can use a nicer handler
		if isatty.IsTerminal(os.Stdout.Fd()) {
			stdoutHandler = tint.NewHandler(os.Stdout, &tint.Options{Level: cli.LogLevel, TimeFormat: time.Kitchen, AddSource: true})
		} else {
			stdoutHandler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cli.LogLevel, AddSource: true})
		}
	}

	if err := cli.run(stdoutHandler); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		kCtx.Exit(1)
	}
}

// run contains the main controller logic and returns any errors encountered
func (cli CLI) run(handler slog.Handler) error {
	initialLogger := internallogger.FromSlog(slog.New(handler))
	ctrl.SetLogger(initialLogger)
	ctx := ctrl.SetupSignalHandler()

	otelConfig := internalotel.Config{
		Mode:           cli.Telemetry.Mode,
		OTLPEndpoint:   cli.Telemetry.Endpoint,
		UseInsecure:    cli.Telemetry.Insecure,
		BatchTimeout:   1 * time.Second,
		MetricInterval: 15 * time.Second,
	}

	configuredSlogLogger, otelShutdown, err := internalotel.SetupTelemetry(ctx, otelConfig, handler)
	if err != nil {
		return fmt.Errorf("unable to set up OpenTelemetry SDK: %w", err)
	}
	defer func() {
		initialLogger.Info("shutting down telemetry...")
		if shutdownErr := otelShutdown(context.Background()); shutdownErr != nil {
			initialLogger.Error(shutdownErr, "telemetry shutdown error")
			err = errors.Join(err, shutdownErr)
		}
	}()

	// Set the logger used by the Kubernetes controller runtime to log to stdout
	// and/or otlp, according to the telemetry mode.
	finalLogrLogger := internallogger.FromSlog(configuredSlogLogger)
	ctrl.SetLogger(finalLogrLogger)
	finalLogrLogger.Info("telemetry initialised", "mode", cli.Telemetry.Mode)

	ghClient, err := github.NewGitHubClient(ctx, configuredSlogLogger, cli.Token, cli.App)
	if err != nil {
		return fmt.Errorf("unable to create GitHub client: %w", err)
	}

	cfg, err := getKubeConfig(cli.Config.KubeContext)
	if err != nil {
		return fmt.Errorf("unable to get kubeconfig: %w", err)
	}

	err = otelruntime.Start(
		otelruntime.WithMinimumReadMemStatsInterval(15 * time.Second),
	)
	if err != nil {
		finalLogrLogger.Error(err, "Failed to start Go runtime metrics")
	}

	options := setupManagerOptions(&cli.Config, finalLogrLogger)

	mgr, err := ctrl.NewManager(cfg, options)
	if err != nil {
		return fmt.Errorf("unable to start manager: %w", err)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("unable to set health check up: %w", err)
	}

	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return fmt.Errorf("unable to set ready check up: %w", err)
	}

	if err = (&tracker.KustomizationReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		Log:    configuredSlogLogger.With("name", "flux-commit-tracker-controller"),
		GitHub: ghClient,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("unable to create controller: %w", err)
	}

	ctrl.Log.Info("starting manager")
	if err := mgr.Start(ctx); err != nil {
		return fmt.Errorf("problem running manager: %w", err)
	}

	return err
}

func getKubeConfig(kubeContext string) (*rest.Config, error) {
	var cfg *rest.Config
	var err error

	log := ctrl.Log.WithName("kubeconfig")

	if kubeContext != "" {
		log.Info("using kubeconfig context", "context", kubeContext)
		cfg, err = config.GetConfigWithContext(kubeContext)
		if err != nil {
			return nil, fmt.Errorf("unable to get kubeconfig with context %s: %w", kubeContext, err)
		}
	} else {
		log.Info("using in-cluster or default kubeconfig")
		cfg, err = config.GetConfig()
		if err != nil {
			return nil, fmt.Errorf("unable to get in-cluster kubernetes config: %w", err)
		}
	}

	return cfg, nil
}

func setupManagerOptions(config *ControllerConfig, logger logr.Logger) manager.Options {
	namespace := os.Getenv("RUNTIME_NAMESPACE")
	if namespace == "" {
		logger.Info("unable to determine runtime namespace, watching fallback namespace", "namespace", FallbackNamespace)
		namespace = FallbackNamespace
	}

	ctrl.Log.Info("watching single namespace", "namespace", namespace)

	return manager.Options{
		Scheme:                 scheme,
		Metrics:                server.Options{BindAddress: config.MetricsAddr},
		HealthProbeBindAddress: config.HealthAddr,
		Cache: cache.Options{
			ByObject: map[client.Object]cache.ByObject{
				&kustomizev1.Kustomization{}: {
					Field: fields.OneTermEqualSelector("metadata.name", fmt.Sprintf("kube-manifests-%s", namespace)),
					Namespaces: map[string]cache.Config{
						namespace: {},
					},
				},
			},
		},
		Logger: logger,
	}
}
