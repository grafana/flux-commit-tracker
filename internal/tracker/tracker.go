package tracker

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	kustomizev1 "github.com/fluxcd/kustomize-controller/api/v1"
	kustomizev1beta2 "github.com/fluxcd/kustomize-controller/api/v1beta2"
	"github.com/grafana/flux-commit-tracker/internal/github"
	otel "go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

const (
	// OtelName is the name used for OpenTelemetry instrumentation.
	OtelName = "github.com/grafana/flux-commit-tracker"

	// OtelNamespace is the namespace used for OpenTelemetry metrics. It's a
	// prefix on all metric names.
	OtelNamespace = "flux_commit_tracker"

	// Metric names
	MetricE2EExportTime                   = OtelNamespace + ".e2e.export-time"
	MetricKubeManifestsExporterExportTime = OtelNamespace + ".kube-manifests-exporter.export-time"
	MetricFluxReconcileTime               = OtelNamespace + ".flux.reconcile-time"
)

var (
	// otel globals
	tracer = otel.Tracer(OtelName)
	meter  = otel.Meter(OtelName)

	// metrics
	exportTime                      metric.Float64Histogram
	kubeManifestsExporterExportTime metric.Float64Histogram
	fluxReconcileTime               metric.Float64Histogram

	// Buckets in seconds: 15s, 30s, 1m, 2m, 3m, 5m, 7m, 10m, 15m, 20m, 30m
	metricBuckets = []float64{
		15, 30, 60, 120, 180, 300, 420, 600, 900, 1200, 1800,
	}
)

func init() {
	var err error

	exportTime, err = meter.Float64Histogram(
		MetricE2EExportTime,
		metric.WithDescription("Time taken from deployment-tools commit to flux apply"),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(metricBuckets...),
	)
	if err != nil {
		panic(fmt.Sprintf("failed to create exportTime histogram: %v", err))
	}

	kubeManifestsExporterExportTime, err = meter.Float64Histogram(
		MetricKubeManifestsExporterExportTime,
		metric.WithDescription("Time taken from deployment-tools commit to kube-manifests commit"),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(metricBuckets...),
	)
	if err != nil {
		panic(fmt.Sprintf("failed to create kubeManifestsExporterExportTime histogram: %v", err))
	}

	fluxReconcileTime, err = meter.Float64Histogram(
		MetricFluxReconcileTime,
		metric.WithDescription("Time taken from kube-manifests commit to flux apply"),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(metricBuckets...),
	)
	if err != nil {
		panic(fmt.Sprintf("failed to create fluxReconcileTime histogram: %v", err))
	}
}

// KustomizationReconciler reconciles a Kustomization object, tracking the time
// taken from deployment-tools commits to flux apply.
type KustomizationReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Log    *slog.Logger
	GitHub github.Client
}

// getKustomization fetches the Kustomization object from the cluster. It
// returns `nil, nil` if the object is not found.
func (r *KustomizationReconciler) getKustomization(ctx context.Context, req ctrl.Request) (*kustomizev1.Kustomization, error) {
	ctx, span := tracer.Start(ctx, "getKustomization", trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()

	var kustomization kustomizev1.Kustomization
	err := r.Get(ctx, req.NamespacedName, &kustomization)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to get Kustomization")
		if apierrors.IsNotFound(err) {
			r.Log.WarnContext(ctx, "kustomization not found, ignoring", "name", req.Name, "namespace", req.Namespace)

			// It's not going to become available, so don't requeue
			return nil, nil
		}

		return nil, fmt.Errorf("failed to get Kustomization: %w", err)
	}

	span.SetAttributes(attribute.String("k8s.resource.uid", string(kustomization.UID)))
	span.SetStatus(codes.Ok, "Successfully retrieved Kustomization")
	return &kustomization, nil
}

// extractReconciledCommit extracts the kube-manifests hash and the time of the
// last successful reconciliation from the Kustomization object.
func extractReconciledCommit(ctx context.Context, log *slog.Logger, k *kustomizev1.Kustomization) (string, time.Time, error) {
	revision := k.Status.LastAppliedRevision

	log = log.With("kustomization.revision", revision)

	if revision == "" {
		return "", time.Time{}, fmt.Errorf("kustomization `%s` has no last applied revision", k.GroupVersionKind().String())
	}

	// master@sha1:123456 (sha1 is a literal, not a variable: it's the hash
	// algorithm)
	parts := strings.Split(revision, ":")
	if len(parts) != 2 {
		log.ErrorContext(ctx, "invalid revision format")

		// Don't requeue, format is unlikely to change
		return "", time.Time{}, nil
	}

	kubeManifestsHash := parts[1]

	var timeApplied time.Time
	for _, condition := range k.Status.Conditions {
		if condition.Reason == kustomizev1beta2.ReconciliationSucceededReason && condition.Status == "True" {
			timeApplied = condition.LastTransitionTime.Time
			break
		}
	}

	if timeApplied.IsZero() {
		log.InfoContext(ctx, "kustomization has not reconciled successfully yet, skipping")

		return "", time.Time{}, fmt.Errorf("kustomization '%s/%s' has not reconciled successfully yet", k.Namespace, k.Name)
	}

	return kubeManifestsHash, timeApplied, nil
}

// recordKubeManifestsMetrics fetches the time of the reconciled commit from
// GitHub's API, and uses it to record related metrics.
func (r *KustomizationReconciler) recordKubeManifestsMetrics(ctx context.Context, log *slog.Logger, repo github.GitHubRepo, hash string, timeApplied time.Time, metricAttributes attribute.Set) (kubeManifestsCommitTime time.Time, err error) {
	ctx, span := tracer.Start(ctx, "recordKubeManifestsMetrics")
	defer span.End()

	log = log.With("repo.kube_manifests.hash", hash, "flux.apply_time", timeApplied.UTC().String())
	log.DebugContext(ctx, "detected flux apply, fetching kube-manifests commit info")

	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	kubeManifestsCommitTime, err = r.GitHub.FetchCommitTime(timeoutCtx, log, repo, hash)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to fetch kube-manifests commit time")

		// Requeue in case of transient GitHub API errors
		return time.Time{}, fmt.Errorf("failed to fetch kube-manifests commit time: %w", err)
	}

	span.SetAttributes(attribute.String("repo.kube_manifests.commit_time", kubeManifestsCommitTime.UTC().String()))
	log = log.With("repo.kube_manifests.commit_time", kubeManifestsCommitTime.UTC().String())

	// Calculate and record time from kube-manifests commit to flux apply
	timeFromKubeManifestsCommitToFluxApply := timeApplied.Sub(kubeManifestsCommitTime)
	fluxReconcileTime.Record(ctx, timeFromKubeManifestsCommitToFluxApply.Seconds(), metric.WithAttributeSet(metricAttributes))

	log.DebugContext(ctx, "calculated flux reconcile time", "duration_seconds", timeFromKubeManifestsCommitToFluxApply.Seconds())
	span.SetStatus(codes.Ok, "Successfully processed kube-manifests commit")

	return kubeManifestsCommitTime, nil
}

// processDeploymentToolsCommits fetches exporter info and processes deployment-tools commits.
func (r *KustomizationReconciler) processDeploymentToolsCommits(
	ctx context.Context,
	log *slog.Logger,
	kubeManifestsRepo github.GitHubRepo,
	kubeManifestsHash string,
	kubeManifestsCommitTime time.Time,
	timeApplied time.Time,
	metricAttributes attribute.Set,
) error {
	ctx, span := tracer.Start(ctx, "processDeploymentToolsCommits")
	defer span.End()

	log.DebugContext(ctx, "fetching exporter info file")

	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	exporterInfoForHash, err := r.GitHub.FetchExporterInfo(timeoutCtx, log, kubeManifestsRepo, kubeManifestsHash)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to fetch exporter info")

		// Requeue in case of transient GitHub API errors
		return fmt.Errorf("failed to fetch exporter info file: %w", err)
	}

	commits := exporterInfoForHash.CommitsSinceLastExport
	span.SetAttributes(attribute.Int("kube_manifests.exporter.info.commits_exported", len(commits)))

	if len(commits) == 0 {
		log.WarnContext(ctx, "found kube-manifests commit with no deployment-tools commits. How did this happen?")
		span.SetStatus(codes.Ok, "No deployment-tools commits found")

		// Even though this is unexpected, it isn't going to change, so don't
		// requeue
		return nil
	}

	log.DebugContext(ctx, "processing deployment-tools commits", "count", len(commits))

	for _, commit := range commits {
		// Calculate and record time from deployment-tools commit to kube-manifests
		// commit (the first part of the process)
		timeFromDeploymentToolsCommitToKubeManifestsCommit := kubeManifestsCommitTime.Sub(commit.Time)
		kubeManifestsExporterExportTime.Record(ctx, timeFromDeploymentToolsCommitToKubeManifestsCommit.Seconds(),
			metric.WithAttributeSet(metricAttributes),
		)

		// Calculate and record total time from deployment-tools commit to flux
		// apply (the total time taken for the process)
		timeFromDeploymentToolsCommitToApply := timeApplied.Sub(commit.Time)
		exportTime.Record(ctx, timeFromDeploymentToolsCommitToApply.Seconds(),
			metric.WithAttributeSet(metricAttributes),
		)

		// This duration is the same for all deployment-tools commits in this batch. This is recor
		timeFromKubeManifestsCommitToFluxApply := timeApplied.Sub(kubeManifestsCommitTime)

		log.InfoContext(
			ctx,
			"calculated deployment times",
			"repo.deployment_tools.hash", commit.Hash,
			"repo.deployment_tools.time", commit.Time.UTC().String(),
			"duration.deployment_tools_commit_to_kube_manifests_commit_seconds", timeFromDeploymentToolsCommitToKubeManifestsCommit.Seconds(),
			"duration.kube_manifests_commit_to_flux_apply_seconds", timeFromKubeManifestsCommitToFluxApply.Seconds(),
			"duration.e2e_deployment_tools_commit_to_flux_apply_seconds", timeFromDeploymentToolsCommitToApply.Seconds(),
		)
	}

	span.SetStatus(codes.Ok, "Successfully processed deployment-tools commits")

	return nil
}

// Reconcile is the main reconciliation loop for Kustomization resources.
func (r *KustomizationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.With("name", req.Name, "namespace", req.Namespace)

	ctx, span := tracer.Start(ctx, "reconcile",
		trace.WithSpanKind(trace.SpanKindConsumer),
		trace.WithAttributes(
			attribute.String("k8s.controller.name", "flux-commit-tracker"),
			attribute.String("k8s.kustomization.name", req.Name),
			attribute.String("k8s.namespace.name", req.Namespace),
			attribute.String("k8s.resource.kind", "Kustomization"),
		),
	)
	defer span.End()

	// 1. Fetch Kustomization
	kustomization, err := r.getKustomization(ctx, req)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to get Kustomization")

		log.ErrorContext(ctx, "failed to get Kustomization", "error", err)

		return ctrl.Result{}, err
	}

	if kustomization == nil {
		span.SetStatus(codes.Ok, "Kustomization not found")
		return ctrl.Result{}, nil
	}
	span.SetAttributes(attribute.String("k8s.resource.uid", string(kustomization.UID)))

	// 2. Extract Data
	kubeManifestsHash, timeApplied, err := extractReconciledCommit(ctx, log, kustomization)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to extract reconciled commit")

		log.ErrorContext(ctx, "failed to extract reconciled commit", "error", err)

		return ctrl.Result{}, err
	}

	span.SetAttributes(attribute.String("repo.kube_manifests.hash", kubeManifestsHash))

	// 3. Process `kube-manifests` commit & metrics
	kubeManifestsRepo := github.GitHubRepo{Owner: "grafana", Repo: "kube-manifests"}
	metricAttributes := attribute.NewSet(
		attribute.String("k8s.resource.name", req.Name),
		attribute.String("k8s.namespace.name", req.Namespace),
	)
	kubeManifestsCommitTime, err := r.recordKubeManifestsMetrics(ctx, log, kubeManifestsRepo, kubeManifestsHash, timeApplied, metricAttributes)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to process kube-manifests metrics")

		log.ErrorContext(ctx, "failed to process kube-manifests metrics", "error", err)

		return ctrl.Result{}, err
	}

	// 4. Process `deployment_tools` commits & metrics
	err = r.processDeploymentToolsCommits(ctx, log, kubeManifestsRepo, kubeManifestsHash, kubeManifestsCommitTime, timeApplied, metricAttributes)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to process deployment-tools commits")

		log.ErrorContext(ctx, "failed to process deployment-tools commits", "error", err)

		return ctrl.Result{}, err
	}

	span.SetStatus(codes.Ok, "Successfully reconciled Kustomization")
	log.InfoContext(ctx, "successfully processed kustomization event")
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager
func (r *KustomizationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.Scheme = mgr.GetScheme()
	return ctrl.NewControllerManagedBy(mgr).
		For(&kustomizev1.Kustomization{}).
		WithEventFilter(kustomizationPredicate{}).
		Complete(r)
}

// kustomizationPredicate filters events before they are passed to the reconciler
type kustomizationPredicate struct {
	predicate.Funcs
}

// Update filters UpdateEvents. It returns true only if the LastAppliedRevision
// status field has changed. This allows us to skip processing events where the
// Kustomization is changed for any other reason.
func (p kustomizationPredicate) Update(e event.UpdateEvent) bool {
	if e.ObjectOld == nil || e.ObjectNew == nil {
		return false // Shouldn't happen normally
	}

	// Only process Kustomization objects
	oldKustomization, okOld := e.ObjectOld.(*kustomizev1.Kustomization)
	newKustomization, okNew := e.ObjectNew.(*kustomizev1.Kustomization)
	if !okOld || !okNew {
		return false
	}

	// Reconcile only if LastAppliedRevision changes and the new revision is not empty
	newRevision := newKustomization.Status.LastAppliedRevision
	if oldKustomization.Status.LastAppliedRevision != newRevision && newRevision != "" {
		// Additionally check if the reconciliation succeeded in the new object
		for _, condition := range newKustomization.Status.Conditions {
			if condition.Reason == kustomizev1beta2.ReconciliationSucceededReason && condition.Status == "True" {
				return true
			}
		}
	}

	return false
}
