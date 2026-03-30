package tracker

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	kustomizev1 "github.com/fluxcd/kustomize-controller/api/v1"
	kustomizev1beta2 "github.com/fluxcd/kustomize-controller/api/v1beta2"
	sourcev1 "github.com/fluxcd/source-controller/api/v1"
	"github.com/grafana/flux-commit-tracker/internal/oci"
	lru "github.com/hashicorp/golang-lru/v2/expirable"
	otel "go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	k8stypes "k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

const (
	// A prefix applied to all metric names
	Prefix = "flux-commit-tracker"

	// Metric names
	MetricE2EExportTime = Prefix + ".e2e.export-time"

	InstrumentationScope = "tracker"

	ociRepositoryKind                 = "OCIRepository"
	kubeManifestsOCIRepositoryName    = "kube-manifests-oci"
	o11yAppsPlatformOCIRepositoryName = "kube-manifests-oci-o11y-apps-platform"
)

var (
	// otel globals
	tracer = otel.Tracer(InstrumentationScope)
	meter  = otel.Meter(InstrumentationScope)

	// metrics
	exportTime metric.Float64Histogram

	// attributes
	attrControllerName = attribute.String("k8s.controller.name", "flux-commit-tracker")
	attrResourceKind   = attribute.String("k8s.resource.kind", "Kustomization")

	commonReconcileAttributes = []attribute.KeyValue{
		attrControllerName,
		attrResourceKind,
	}
)

func init() {
	var err error

	exportTime, err = meter.Float64Histogram(
		MetricE2EExportTime,
		metric.WithDescription("Time taken from deployment-tools commit to flux apply"),
		metric.WithUnit("s"),
	)
	if err != nil {
		panic(fmt.Sprintf("failed to create exportTime histogram: %v", err))
	}
}

// KustomizationReconciler reconciles a Kustomization object, tracking the time
// taken from deployment-tools commits to flux apply.
type KustomizationReconciler struct {
	client.Client
	Scheme            *runtime.Scheme
	Log               *slog.Logger
	OCI               oci.Resolver
	exporterInfoCache *lru.LRU[exporterInfoCacheKey, oci.ExporterInfo]
}

type reconciledState struct {
	SourceKind          string
	SourceName          string
	SourceNamespace     string
	LastAppliedRevision string
	TimeApplied         time.Time
}

func isTrackedKustomization(k *kustomizev1.Kustomization) bool {
	if k.Spec.SourceRef.Kind != ociRepositoryKind {
		return false
	}

	switch k.Spec.SourceRef.Name {
	case kubeManifestsOCIRepositoryName, o11yAppsPlatformOCIRepositoryName:
		return true
	default:
		return false
	}
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

// extractReconciledState extracts source/revision metadata and the time of the
// last successful reconciliation from the Kustomization object.
func extractReconciledState(ctx context.Context, log *slog.Logger, k *kustomizev1.Kustomization) (reconciledState, error) {
	revision := k.Status.LastAppliedRevision
	sourceKind := k.Spec.SourceRef.Kind
	sourceNamespace := k.Spec.SourceRef.Namespace

	log = log.With("kustomization.revision", revision, "kustomization.sourceKind", sourceKind)

	if revision == "" {
		return reconciledState{}, fmt.Errorf("kustomization `%s` has no last applied revision", k.GroupVersionKind().String())
	}

	var timeApplied time.Time
	for _, condition := range k.Status.Conditions {
		if condition.Reason == kustomizev1beta2.ReconciliationSucceededReason && condition.Status == "True" {
			timeApplied = condition.LastTransitionTime.Time
			break
		}
	}

	if timeApplied.IsZero() {
		log.InfoContext(ctx, "kustomization has not reconciled successfully yet, skipping")

		return reconciledState{}, fmt.Errorf("kustomization '%s/%s' has not reconciled successfully yet", k.Namespace, k.Name)
	}

	return reconciledState{
		SourceKind:          sourceKind,
		SourceName:          k.Spec.SourceRef.Name,
		SourceNamespace:     sourceNamespace,
		LastAppliedRevision: revision,
		TimeApplied:         timeApplied,
	}, nil
}

// processDeploymentToolsCommits processes deployment_tools commits from
// exporter-info metadata.
func (r *KustomizationReconciler) processDeploymentToolsCommits(
	ctx context.Context,
	log *slog.Logger,
	exporterInfo oci.ExporterInfo,
	timeApplied time.Time,
	metricAttributes attribute.Set,
) error {
	ctx, span := tracer.Start(ctx, "processDeploymentToolsCommits")
	defer span.End()

	commits := exporterInfo.CommitsSinceLastExport
	span.SetAttributes(attribute.Int("kube_manifests.exporter.info.commits_exported", len(commits)))

	if len(commits) == 0 {
		log.WarnContext(ctx, "exporter-info contains no deployment-tools commits")
		span.SetStatus(codes.Ok, "No deployment-tools commits found")

		// Even though this is unexpected, it isn't going to change, so don't
		// requeue
		return nil
	}

	log.DebugContext(ctx, "processing deployment-tools commits", "count", len(commits))

	for _, commit := range commits {
		// Calculate and record total time from deployment-tools commit to flux
		// apply (the total time taken for the process)
		timeFromDeploymentToolsCommitToApply := timeApplied.Sub(commit.Time)
		exportTime.Record(ctx, timeFromDeploymentToolsCommitToApply.Seconds(),
			metric.WithAttributeSet(metricAttributes),
		)

		logAttributes := []any{
			"repo.deployment_tools.hash", commit.Hash,
			"repo.deployment_tools.time", commit.Time.UTC().String(),
			"duration.e2e_deployment_tools_commit_to_flux_apply_seconds", timeFromDeploymentToolsCommitToApply.Seconds(),
		}

		log.InfoContext(ctx, "calculated deployment times", logAttributes...)
	}

	span.SetStatus(codes.Ok, "Successfully processed deployment-tools commits")

	return nil
}

func (r *KustomizationReconciler) fetchExporterInfoFromOCI(ctx context.Context, log *slog.Logger, sourceNamespace, sourceName, appliedRevision string) (oci.ExporterInfo, error) {
	repositoryURL, err := r.getOCIRepositoryURL(ctx, sourceNamespace, sourceName)
	if err != nil {
		return oci.ExporterInfo{}, fmt.Errorf("failed to resolve OCIRepository URL: %w", err)
	}

	cacheKey := exporterInfoCacheKey{
		repositoryURL: repositoryURL,
		revision:      appliedRevision,
	}
	if info, ok := r.exporterInfoCache.Get(cacheKey); ok {
		log.DebugContext(ctx, "reusing cached exporter-info", "oci.repository_url", repositoryURL, "kustomization.revision", appliedRevision)
		return info, nil
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	info, err := r.OCI.FetchExporterInfo(timeoutCtx, log, repositoryURL, appliedRevision)
	if err != nil {
		return oci.ExporterInfo{}, fmt.Errorf("failed to fetch exporter info from OCI layer: %w", err)
	}

	r.exporterInfoCache.Add(cacheKey, info)
	return info, nil
}

func (r *KustomizationReconciler) getOCIRepositoryURL(ctx context.Context, namespace, name string) (string, error) {
	ociRepository := &sourcev1.OCIRepository{}

	if err := r.Get(ctx, k8stypes.NamespacedName{Namespace: namespace, Name: name}, ociRepository); err != nil {
		return "", err
	}

	return ociRepository.Spec.URL, nil
}

// Reconcile is the main reconciliation loop for Kustomization resources.
func (r *KustomizationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.With("name", req.Name, "namespace", req.Namespace)

	spanAttributes := append(
		commonReconcileAttributes,
		attribute.String("k8s.resource.name", req.Name),
		attribute.String("k8s.namespace.name", req.Namespace),
	)

	ctx, span := tracer.Start(ctx, "reconcile",
		trace.WithSpanKind(trace.SpanKindConsumer),
		trace.WithAttributes(spanAttributes...),
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

	if !isTrackedKustomization(kustomization) {
		span.SetStatus(codes.Ok, "Kustomization is outside tracker scope")
		log.DebugContext(ctx, "ignoring unsupported kustomization")
		return ctrl.Result{}, nil
	}

	// 2. Extract Data
	state, err := extractReconciledState(ctx, log, kustomization)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to extract reconciled state")

		log.ErrorContext(ctx, "failed to extract reconciled state", "error", err)

		return ctrl.Result{}, err
	}

	span.SetAttributes(
		attribute.String("k8s.source.kind", state.SourceKind),
		attribute.String("k8s.source.name", state.SourceName),
		attribute.String("k8s.source.namespace", state.SourceNamespace),
		attribute.String("kustomization.revision", state.LastAppliedRevision),
	)

	metricAttributes := attribute.NewSet(
		attribute.String("k8s.resource.name", req.Name),
		attribute.String("k8s.namespace.name", req.Namespace),
		attribute.String("k8s.source.kind", state.SourceKind),
	)

	exporterInfo, err := r.fetchExporterInfoFromOCI(ctx, log, state.SourceNamespace, state.SourceName, state.LastAppliedRevision)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to fetch exporter-info from OCI")

		log.ErrorContext(ctx, "failed to fetch exporter-info from OCI", "error", err)

		return ctrl.Result{}, err
	}

	// 3. Process `deployment_tools` commits & metrics
	err = r.processDeploymentToolsCommits(ctx, log, exporterInfo, state.TimeApplied, metricAttributes)
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
	r.exporterInfoCache = newExporterInfoCache()
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

	if !isTrackedKustomization(newKustomization) {
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
