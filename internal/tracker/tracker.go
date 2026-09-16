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
	otel "go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
)

const (
	// A prefix applied to all metric names
	Prefix = "flux-commit-tracker"

	// Metric names
	MetricE2EExportTime      = Prefix + ".e2e.export-time"
	MetricOCIPushToApplyTime = Prefix + ".oci.push-to-apply-time"

	InstrumentationScope = "tracker"
)

var (
	// otel globals
	tracer = otel.Tracer(InstrumentationScope)

	// attributes
	attrControllerName = attribute.String("k8s.controller.name", "flux-commit-tracker")
	attrResourceKind   = attribute.String("k8s.resource.kind", "Kustomization")

	commonReconcileAttributes = []attribute.KeyValue{
		attrControllerName,
		attrResourceKind,
	}
)

// Metrics holds the cycle-time histograms used by a reconciler.
type Metrics struct {
	exportTime         metric.Float64Histogram
	ociPushToApplyTime metric.Float64Histogram
}

// NewMetrics sets up the tracker's cycle-time metrics.
func NewMetrics(meter metric.Meter) (*Metrics, error) {
	metrics := &Metrics{}
	var err error

	metrics.exportTime, err = meter.Float64Histogram(
		MetricE2EExportTime,
		metric.WithDescription("Time taken from deployment-tools commit to flux apply"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, fmt.Errorf("create exportTime histogram: %w", err)
	}

	metrics.ociPushToApplyTime, err = meter.Float64Histogram(
		MetricOCIPushToApplyTime,
		metric.WithDescription("Time from OCI push start to successful Flux reconciliation, including upload and discovery delay"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, fmt.Errorf("create ociPushToApplyTime histogram: %w", err)
	}
	return metrics, nil
}

// KustomizationReconciler reconciles a Kustomization object, tracking the time
// taken from deployment-tools commits to flux apply.
type KustomizationReconciler struct {
	client.Client
	Log     *slog.Logger
	OCI     oci.Resolver
	Metrics *Metrics
}

type reconciledState struct {
	SourceKind          string
	SourceName          string
	SourceNamespace     string
	LastAppliedRevision string
	TimeApplied         time.Time
}

// measurementRequest saves the revision and apply time when an update arrives,
// so later reconciliations cannot change the measurement.
type measurementRequest struct {
	k8stypes.NamespacedName
	UID k8stypes.UID
	reconciledState
}

// extractReconciledState extracts source/revision metadata and the time of the
// last successful reconciliation from the Kustomization object.
func extractReconciledState(k *kustomizev1.Kustomization) (reconciledState, error) {
	revision := k.Status.LastAppliedRevision
	sourceKind := k.Spec.SourceRef.Kind
	sourceNamespace := k.Spec.SourceRef.Namespace

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

// recordOCIPushToApplyTime measures OCI push start to successful reconciliation
// in the cluster. Each processed image revision produces one observation.
func (r *KustomizationReconciler) recordOCIPushToApplyTime(ctx context.Context, log *slog.Logger, pushStart, timeApplied time.Time, attributes attribute.Set) {
	if pushStart.IsZero() {
		log.DebugContext(ctx, "OCI push-start timestamp missing, skipping metric")
		return
	}
	if timeApplied.Before(pushStart) {
		log.WarnContext(ctx, "invalid OCI push-to-apply interval, skipping metric", "push_start", pushStart, "time_applied", timeApplied)
		return
	}
	duration := timeApplied.Sub(pushStart).Seconds()
	r.Metrics.ociPushToApplyTime.Record(ctx, duration, metric.WithAttributeSet(attributes))
}

// processDeploymentToolsCommits processes deployment_tools commits from
// exporter-info metadata.
func (r *KustomizationReconciler) processDeploymentToolsCommits(
	ctx context.Context,
	log *slog.Logger,
	exporterInfo oci.ExporterInfo,
	timeApplied time.Time,
	metricAttributes attribute.Set,
) {
	ctx, span := tracer.Start(ctx, "processDeploymentToolsCommits")
	defer span.End()

	commits := exporterInfo.CommitsSinceLastExport
	span.SetAttributes(attribute.Int("kube_manifests.exporter.info.commits_exported", len(commits)))

	if len(commits) == 0 {
		log.WarnContext(ctx, "exporter-info contains no deployment-tools commits")
		span.SetStatus(codes.Ok, "No deployment-tools commits found")

		return
	}

	log.DebugContext(ctx, "processing deployment-tools commits", "count", len(commits))

	for _, commit := range commits {
		// Calculate and record total time from deployment-tools commit to flux
		// apply (the total time taken for the process)
		timeFromDeploymentToolsCommitToApply := timeApplied.Sub(commit.Time)
		r.Metrics.exportTime.Record(ctx, timeFromDeploymentToolsCommitToApply.Seconds(),
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

}

func (r *KustomizationReconciler) fetchArtifactInfoFromOCI(ctx context.Context, log *slog.Logger, sourceNamespace, sourceName, appliedRevision string) (oci.ArtifactInfo, error) {
	repositoryURL, err := r.getOCIRepositoryURL(ctx, sourceNamespace, sourceName)
	if err != nil {
		return oci.ArtifactInfo{}, fmt.Errorf("failed to resolve OCIRepository URL: %w", err)
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	info, err := r.OCI.FetchArtifactInfo(timeoutCtx, log, repositoryURL, appliedRevision)
	if err != nil {
		return oci.ArtifactInfo{}, fmt.Errorf("failed to fetch artifact info from OCI: %w", err)
	}

	return info, nil
}

func (r *KustomizationReconciler) getOCIRepositoryURL(ctx context.Context, namespace, name string) (string, error) {
	ociRepository := &sourcev1.OCIRepository{}

	if err := r.Get(ctx, k8stypes.NamespacedName{Namespace: namespace, Name: name}, ociRepository); err != nil {
		return "", err
	}

	return ociRepository.Spec.URL, nil
}

// Reconcile processes a successful revision apply. Retries reuse
// the same revision and apply time so later reconciliations cannot
// change the measurement.
func (r *KustomizationReconciler) Reconcile(ctx context.Context, req measurementRequest) (ctrl.Result, error) {
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

	state := req.reconciledState
	span.SetAttributes(attribute.String("k8s.resource.uid", string(req.UID)))

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

	artifactInfo, err := r.fetchArtifactInfoFromOCI(ctx, log, state.SourceNamespace, state.SourceName, state.LastAppliedRevision)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to fetch artifact info from OCI")

		log.ErrorContext(ctx, "failed to fetch artifact info from OCI", "error", err)

		return ctrl.Result{}, err
	}

	r.recordOCIPushToApplyTime(ctx, log, artifactInfo.PushStartTime, state.TimeApplied, metricAttributes)

	// Record end-to-end latency for each deployment_tools commit.
	r.processDeploymentToolsCommits(ctx, log, artifactInfo.ExporterInfo, state.TimeApplied, metricAttributes)

	span.SetStatus(codes.Ok, "Successfully reconciled Kustomization")
	log.InfoContext(ctx, "successfully processed kustomization event")
	return ctrl.Result{}, nil
}

// SetupWithManager watches for successful revision changes.
// Existing revisions discovered at startup do not generate measurements,
// because their latest reconciliation time may be later than
// when they first applied.
func (r *KustomizationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return builder.TypedControllerManagedBy[measurementRequest](mgr).
		Named("kustomization").
		Watches(&kustomizev1.Kustomization{}, handler.TypedFuncs[client.Object, measurementRequest]{
			UpdateFunc: func(ctx context.Context, e event.UpdateEvent, q workqueue.TypedRateLimitingInterface[measurementRequest]) {
				previousKustomizationState := e.ObjectOld.(*kustomizev1.Kustomization)
				updatedKustomizationState := e.ObjectNew.(*kustomizev1.Kustomization)

				// Flux reconciles the same revision repeatedly. We skip these updates
				// so we only measure when a different revision is applied.
				if previousKustomizationState.Status.LastAppliedRevision == updatedKustomizationState.Status.LastAppliedRevision {
					return
				}

				log := r.Log.With("name", updatedKustomizationState.Name, "namespace", updatedKustomizationState.Namespace)
				state, err := extractReconciledState(updatedKustomizationState)
				if err != nil {
					log.DebugContext(ctx, "revision update has no successful apply timestamp", "error", err)
					return
				}

				q.Add(measurementRequest{
					NamespacedName: k8stypes.NamespacedName{
						Namespace: updatedKustomizationState.Namespace,
						Name:      updatedKustomizationState.Name,
					},
					UID:             updatedKustomizationState.UID,
					reconciledState: state,
				})
			},
		}).
		Complete(r)
}
