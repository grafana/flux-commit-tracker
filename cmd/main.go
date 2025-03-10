package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	kustomizev1 "github.com/fluxcd/kustomize-controller/api/v1"
	kustomizev1beta2 "github.com/fluxcd/kustomize-controller/api/v1beta2"
	"github.com/go-logr/logr"
	"github.com/grafana/flux-commit-tracker/internal/github"
	internalotel "github.com/grafana/flux-commit-tracker/internal/otel"
	"go.opentelemetry.io/contrib/bridges/otelslog"
	otelruntime "go.opentelemetry.io/contrib/instrumentation/runtime"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

const (
	// FallbackNamespace is the namespace to look for a Kustomization in if the
	// runtime namespace is not available
	FallbackNamespace = "default"

	// OtelName is the name used for OpenTelemetry instrumentation
	OtelName = "github.com/grafana/flux-commit-tracker"
)

var (
	// k8s controller
	scheme = runtime.NewScheme()

	tracer     = otel.Tracer(OtelName)
	meter      = otel.Meter(OtelName)
	exportTime metric.Float64Histogram
)

func init() {
	// k8s controller initialisation
	_ = clientgoscheme.AddToScheme(scheme)
	_ = kustomizev1.AddToScheme(scheme)
	_ = kustomizev1beta2.AddToScheme(scheme)

	// otel initialisation
	var err error
	exportTime, err = meter.Float64Histogram(
		"e2e_export_time_seconds",
		metric.WithDescription("Time taken to export manifests"),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(
			// Buckets in seconds: 15s, 30s, 1m, 2m, 3m, 5m, 7m, 10m, 15m, 20m, 30m
			15, 30, 60, 120, 180, 300, 420, 600, 900, 1200, 1800,
		),
	)
	if err != nil {
		panic(err)
	}
}

type ControllerConfig struct {
	KubeContext        string
	MetricsAddr        string
	HealthAddr         string
	WatchAllNamespaces bool
	Concurrent         int

	TelemetryExporter string // "stdout" or "otlp"
	TelemetryEndpoint string // Address of collector, e.g., "localhost:4317"
	TelemetryInsecure bool   // Whether to use insecure connection for OTLP
}

func main() {
	config := &ControllerConfig{
		MetricsAddr: ":8080",
		HealthAddr:  ":9440",

		TelemetryExporter: "stdout",
		TelemetryEndpoint: "localhost:4317",
		TelemetryInsecure: true,
	}

	flag.StringVar(&config.MetricsAddr, "metrics-addr", config.MetricsAddr, "The address the metric endpoint binds to.")
	flag.StringVar(&config.HealthAddr, "health-addr", config.HealthAddr, "The address the health endpoint binds to.")
	flag.StringVar(&config.KubeContext, "kube-context", config.KubeContext, "The name of the kubeconfig context to use.")

	// Telemetry flags
	flag.StringVar(&config.TelemetryExporter, "telemetry-exporter", config.TelemetryExporter,
		"Telemetry exporter type (stdout, otlp)")
	flag.StringVar(&config.TelemetryEndpoint, "telemetry-endpoint", config.TelemetryEndpoint,
		"Endpoint for telemetry collector (e.g., localhost:4317)")
	flag.BoolVar(&config.TelemetryInsecure, "telemetry-insecure", config.TelemetryInsecure,
		"Use insecure connection for telemetry")

	flag.Parse()

	otelHandler := otelslog.NewHandler(OtelName)
	logger := logr.FromSlogHandler(otelHandler)
	ctrl.SetLogger(logger)

	client := github.NewGitHubClient(context.Background(), logger, "token")

	if err := run(config, client); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// run contains the main controller logic and returns any errors encountered
func run(config *ControllerConfig, client *github.GitHub) error {
	ctx := ctrl.SetupSignalHandler()

	otelConfig := internalotel.Config{
		ServiceName:    OtelName,
		ExporterType:   internalotel.ExporterType(config.TelemetryExporter),
		OTLPEndpoint:   config.TelemetryEndpoint,
		UseInsecure:    config.TelemetryInsecure,
		BatchTimeout:   1 * time.Second,
		MetricInterval: 15 * time.Second,
	}

	otelShutdown, err := internalotel.SetupOTelSDK(ctx, otelConfig)
	if err != nil {
		return fmt.Errorf("unable to set up OpenTelemetry SDK: %w", err)
	}
	defer func() {
		if shutdownErr := otelShutdown(context.Background()); shutdownErr != nil {
			err = errors.Join(err, shutdownErr)
		}
	}()

	// Go runtime metrics
	err = otelruntime.Start(
		// Don't collect metrics more than this frequently
		otelruntime.WithMinimumReadMemStatsInterval(15 * time.Second),
	)
	if err != nil {
		return fmt.Errorf("unable to start runtime metrics: %w", err)
	}

	cfg, err := getKubeConfig(config.KubeContext)
	if err != nil {
		return fmt.Errorf("unable to get kubeconfig: %w", err)
	}

	options := setupManagerOptions(config)

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

	if err = setupController(mgr, client); err != nil {
		return fmt.Errorf("unable to set controllers up: %w", err)
	}

	ctrl.Log.Info("starting manager")
	if err := mgr.Start(ctx); err != nil {
		return fmt.Errorf("problem running manager: %w", err)
	}

	return nil
}

func getKubeConfig(kubeContext string) (*rest.Config, error) {
	var cfg *rest.Config
	var err error

	if kubeContext != "" {
		ctrl.Log.Info("using kubeconfig context", "context", kubeContext)
		cfg, err = config.GetConfigWithContext(kubeContext)
		if err != nil {
			return nil, fmt.Errorf("unable to get kubeconfig with context %s: %w", kubeContext, err)
		}
	} else {
		cfg, err = config.GetConfig()
		if err != nil {
			return nil, fmt.Errorf("unable to get in-cluster kubernetes config: %w", err)
		}
	}

	return cfg, nil
}

func setupManagerOptions(config *ControllerConfig) manager.Options {
	namespace := os.Getenv("RUNTIME_NAMESPACE")
	if namespace == "" {
		ctrl.Log.Info("unable to determine runtime namespace, watching fallback namespace", "namespace", FallbackNamespace)
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
	}
}

// KustomizationReconciler reconciles a Kustomization object
type KustomizationReconciler struct {
	client.Client

	log          logr.Logger
	githubClient *github.GitHub
}

func setupController(mgr ctrl.Manager, client *github.GitHub) error {
	return (&KustomizationReconciler{
		Client: mgr.GetClient(),

		log:          ctrl.Log.WithName("controllers").WithName("kustomization"),
		githubClient: client,
	}).SetupWithManager(mgr)
}

func (r *KustomizationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&kustomizev1.Kustomization{}).
		WithEventFilter(kustomizationPredicate{}).
		Complete(r)
}

// Reconcile is the main reconciliation loop for Kustomization resources
func (r *KustomizationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	ctx, span := tracer.Start(ctx, "reconcile",
		trace.WithAttributes(
			attribute.String("controller", "kustomization"),
			attribute.String("name", req.Name),
			attribute.String("namespace", req.Namespace),
		),
	)
	defer span.End()

	// Create a subspan for the Get operation
	getCtx, getSpan := tracer.Start(ctx, "k8s.get.kustomization",
		trace.WithAttributes(
			attribute.String("k8s.resource.name", req.Name),
			attribute.String("k8s.resource.namespace", req.Namespace),
			attribute.String("k8s.resource.kind", "Kustomization"),
		))
	var kustomization kustomizev1.Kustomization
	err := r.Get(getCtx, req.NamespacedName, &kustomization)
	if err != nil {
		getSpan.RecordError(err)
		getSpan.SetStatus(codes.Error, "Failed to get Kustomization")
		getSpan.End()

		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	getSpan.SetStatus(codes.Ok, "Successfully retrieved Kustomization")
	getSpan.End()

	revision := kustomization.Status.LastAppliedRevision

	if revision == "" {
		return ctrl.Result{}, nil
	}

	// master@hash1:123456
	parts := strings.Split(revision, ":")
	if len(parts) != 2 {
		return ctrl.Result{}, fmt.Errorf("invalid revision format (expected ref@hash:hash): %s", revision)
	}

	hash := parts[1]

	conditions := kustomization.Status.Conditions

	var timeApplied time.Time
	for _, condition := range conditions {
		if condition.Reason != kustomizev1beta2.ReconciliationSucceededReason {
			continue
		}

		timeApplied = condition.LastTransitionTime.Time
		break
	}

	log := r.log.WithValues("kube_manifests_hash", hash, "flux_apply_time", timeApplied.UTC().String())
	log.Info("detected flux apply")

	timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Call GitHub client without adding spans here - the GitHub package handles its own tracing
	exporterInfoForHash, err := r.githubClient.FetchCommitInfo(timeoutCtx, github.GitHubRepo{
		Owner: "grafana",
		Repo:  "kube-manifests",
	}, hash)

	if err != nil {
		log.Error(err, "failed to fetch commit info")
		span.RecordError(err)
		return ctrl.Result{}, err
	}

	commits := exporterInfoForHash.CommitsSinceLastExport

	// Record metric for how many commits we processed
	span.SetAttributes(attribute.Int("reconcile.commits_processed", len(commits)))

	for _, commit := range commits {
		timeSinceCommit := timeApplied.Sub(commit.Time)

		exportTime.Record(ctx, timeSinceCommit.Seconds(),
			metric.WithAttributes(
				attribute.String("kustomization_name", req.Name),
				attribute.String("kustomization_namespace", req.Namespace),
			),
		)
		log.Info(
			"commit info",
			"deployment_tools_hash", commit.Hash,
			"commit_time", commit.Time.UTC().String(),
			"time_to_apply_seconds", timeSinceCommit.Seconds(),
		)
	}

	return ctrl.Result{}, nil
}

// kustomizationPredicate filters events before they are passed to the reconciler
type kustomizationPredicate struct {
	predicate.Funcs
}

func (p kustomizationPredicate) Update(e event.UpdateEvent) bool {
	if e.ObjectOld == nil || e.ObjectNew == nil {
		return false
	}

	oldKustomization := e.ObjectOld.(*kustomizev1.Kustomization)
	newKustomization := e.ObjectNew.(*kustomizev1.Kustomization)

	// We're especially interested in changes to LastAppliedRevision
	if oldKustomization.Status.LastAppliedRevision != newKustomization.Status.LastAppliedRevision {
		return true
	}

	return false
}
