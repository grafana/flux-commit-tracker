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
		fmt.Sprintf("%s.e2e.export-time", OtelNamespace),
		metric.WithDescription("Time taken from deployment-tools commit to flux apply"),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(metricBuckets...),
	)
	if err != nil {
		panic(fmt.Sprintf("failed to create exportTime histogram: %v", err))
	}

	kubeManifestsExporterExportTime, err = meter.Float64Histogram(
		fmt.Sprintf("%s.kube-manifests-exporter.export-time", OtelNamespace),
		metric.WithDescription("Time taken from deployment-tools commit to kube-manifests commit"),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(metricBuckets...),
	)
	if err != nil {
		panic(fmt.Sprintf("failed to create kubeManifestsExporterExportTime histogram: %v", err))
	}

	fluxReconcileTime, err = meter.Float64Histogram(
		fmt.Sprintf("%s.flux.reconcile-time", OtelNamespace),
		metric.WithDescription("Time taken from kube-manifests commit to flux apply"),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(metricBuckets...),
	)
	if err != nil {
		panic(fmt.Sprintf("failed to create fluxReconcileTime histogram: %v", err))
	}
}

// KustomizationReconciler reconciles a Kustomization object
type KustomizationReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Log    *slog.Logger
	GitHub github.GitHub
}

// Reconcile is the main reconciliation loop for Kustomization resources. This
// is where we respond to the flux apply event and calculate the time taken to
// apply the manifests.
func (r *KustomizationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
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

	log := r.Log.With("name", req.Name, "namespace", req.Namespace)

	// Create a subspan for the Get operation
	getCtx, getSpan := tracer.Start(ctx, "k8s.get.kustomization",
		trace.WithSpanKind(trace.SpanKindClient),
	)

	var kustomization kustomizev1.Kustomization
	err := r.Get(getCtx, req.NamespacedName, &kustomization)
	if err != nil {
		getSpan.RecordError(err)
		getSpan.SetStatus(codes.Error, "Failed to get Kustomization")
		getSpan.End()

		if apierrors.IsNotFound(err) {
			log.WarnContext(ctx, "kustomization not found, ignoring")
			return ctrl.Result{}, nil
		}

		log.ErrorContext(ctx, "failed to get kustomization", "error", err)
		return ctrl.Result{}, err
	}

	span.SetAttributes(attribute.String("k8s.resource.uid", string(kustomization.UID)))

	getSpan.SetStatus(codes.Ok, "Successfully retrieved Kustomization")
	getSpan.End()

	revision := kustomization.Status.LastAppliedRevision
	if revision == "" {
		log.InfoContext(ctx, "kustomization has no last applied revision yet, skipping")
		return ctrl.Result{}, nil
	}

	// master@hash1:123456
	parts := strings.Split(revision, ":")
	if len(parts) != 2 {
		log.ErrorContext(ctx, "invalid revision format (expected ref@hash:hash)", "revision", revision)
		span.SetStatus(codes.Error, "Invalid revision format")

		// Don't requeue (which returning an error would do), the revision format is
		// unlikely to change on its own.
		return ctrl.Result{}, nil
	}

	kubeManifestsHash := parts[1]
	kubeManifestsRepo := github.GitHubRepo{
		Owner: "grafana",
		Repo:  "kube-manifests",
	}

	conditions := kustomization.Status.Conditions

	var timeApplied time.Time
	for _, condition := range conditions {
		if condition.Reason != kustomizev1beta2.ReconciliationSucceededReason {
			continue
		}

		timeApplied = condition.LastTransitionTime.Time
		break
	}

	if timeApplied.IsZero() {
		log.InfoContext(ctx, "kustomization has not reconciled successfully yet, skipping")

		return ctrl.Result{}, nil
	}

	span.SetAttributes(attribute.String("repo.kube_manifests.hash", kubeManifestsHash))

	log = log.With("repo.kube_manifests.hash", kubeManifestsHash, "flux.apply_time", timeApplied.UTC().String())
	log.DebugContext(ctx, "detected flux apply, fetching kube-manifests commit info")

	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	kubeManifestsCommitTime, err := r.GitHub.FetchCommitTime(timeoutCtx, log, kubeManifestsRepo, kubeManifestsHash)
	if err != nil {
		log.ErrorContext(ctx, "failed to fetch kube-manifests commit time", "error", err, "repo", kubeManifestsRepo, "hash", kubeManifestsHash)
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to fetch kube-manifests commit time")

		// Requeue in case of transient GitHub API errors
		return ctrl.Result{}, err
	}

	log = log.With("repo.kube_manifests.commit_time", kubeManifestsCommitTime.UTC().String())

	// Calculate and record time from kube-manifests commit to flux apply (the
	// second part of the process)
	timeFromKubeManifestsCommitToFluxApply := timeApplied.Sub(kubeManifestsCommitTime)
	metricAttributes := attribute.NewSet(
		attribute.String("k8s.resource.name", req.Name),
		attribute.String("k8s.namespace.name", req.Namespace),
	)
	fluxReconcileTime.Record(ctx, timeFromKubeManifestsCommitToFluxApply.Seconds(), metric.WithAttributeSet(metricAttributes))

	log.DebugContext(ctx, "calculated flux reconcile time", "duration_seconds", timeFromKubeManifestsCommitToFluxApply.Seconds())

	log.DebugContext(ctx, "fetching exporter info file")

	kubeManifests := github.GitHubRepo{
		Owner: "grafana",
		Repo:  "kube-manifests",
	}
	exporterInfoForHash, err := r.GitHub.FetchExporterInfo(timeoutCtx, log, kubeManifests, kubeManifestsHash)
	if err != nil {
		log.ErrorContext(ctx, "failed to fetch exporter info file", "error", err, "repo", kubeManifests, "hash", kubeManifestsHash)
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to fetch exporter info")

		// Requeue in case of transient GitHub API errors
		return ctrl.Result{}, err
	}

	commits := exporterInfoForHash.CommitsSinceLastExport
	span.SetAttributes(attribute.Int("kube_manifests.exporter.info.commits_exported", len(commits)))

	if len(commits) == 0 {
		log.WarnContext(ctx, "found kube-manifests commit with no deployment-tools commits. How did this happen?")

		// Even though this is unexpected, it isn't going to change, so don't
		// requeue
		return ctrl.Result{}, nil
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

		log.InfoContext(
			ctx,
			"calculated deployment times",
			"repo.deployment_tools.hash", commit.Hash,
			"repo.deployment_tools.time", commit.Time.UTC().String(),
			"duration.deployment_tools_commit_to_kube_manifests_commit_seconds", timeFromDeploymentToolsCommitToKubeManifestsCommit.Seconds(),
			"duration.kube_manifests_commit_to_flux_apply_seconds", timeFromKubeManifestsCommitToFluxApply.Seconds(), // This is the same for all deployment-tools commits in this batch
			"duration.e2e_deployment_tools_commit_to_flux_apply_seconds", timeFromDeploymentToolsCommitToApply.Seconds(),
		)
	}

	span.SetStatus(codes.Ok, "Successfully processed deployment-tools commits")

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
// status field has changed.
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
