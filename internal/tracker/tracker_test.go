package tracker

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	kustomizev1 "github.com/fluxcd/kustomize-controller/api/v1"
	kustomizev1beta2 "github.com/fluxcd/kustomize-controller/api/v1beta2"
	sourcev1 "github.com/fluxcd/source-controller/api/v1"
	"github.com/grafana/flux-commit-tracker/internal/oci"
	"github.com/grafana/flux-commit-tracker/internal/otel"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type fakeOCIResolver struct {
	ArtifactInfo oci.ArtifactInfo
	FetchErr     error
	Revisions    []string
}

func (f *fakeOCIResolver) FetchArtifactInfo(ctx context.Context, log *slog.Logger, repositoryURL, appliedRevision string) (oci.ArtifactInfo, error) {
	f.Revisions = append(f.Revisions, appliedRevision)

	if f.FetchErr != nil {
		return oci.ArtifactInfo{}, f.FetchErr
	}

	return f.ArtifactInfo, nil
}

func setupScheme(t *testing.T) *runtime.Scheme {
	t.Helper()

	scheme := runtime.NewScheme()
	err := kustomizev1.AddToScheme(scheme)
	require.NoError(t, err)

	err = sourcev1.AddToScheme(scheme)
	require.NoError(t, err)

	return scheme
}

func makeOCIRepositoryObject(namespace, name, url string) *sourcev1.OCIRepository {
	return &sourcev1.OCIRepository{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: sourcev1.OCIRepositorySpec{
			URL: url,
		},
	}
}

func makeOCIKustomizationObject(namespace, name, sourceNamespace, sourceName, appliedRevision string, timeApplied time.Time) *kustomizev1.Kustomization {
	return &kustomizev1.Kustomization{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			UID:       types.UID("test-uid"),
		},
		Spec: kustomizev1.KustomizationSpec{
			SourceRef: kustomizev1.CrossNamespaceSourceReference{
				Kind:      "OCIRepository",
				Name:      sourceName,
				Namespace: sourceNamespace,
			},
		},
		Status: kustomizev1.KustomizationStatus{
			LastAppliedRevision: appliedRevision,
			Conditions: []metav1.Condition{
				{
					Type:               "Ready",
					Status:             metav1.ConditionTrue,
					Reason:             kustomizev1beta2.ReconciliationSucceededReason,
					LastTransitionTime: metav1.Time{Time: timeApplied},
				},
			},
		},
	}
}

func makeMeasurementRequest(t *testing.T, kustomization *kustomizev1.Kustomization) measurementRequest {
	t.Helper()
	state, err := extractReconciledState(kustomization)
	require.NoError(t, err)
	return measurementRequest{
		NamespacedName: types.NamespacedName{
			Name:      kustomization.Name,
			Namespace: kustomization.Namespace,
		},
		UID:             kustomization.UID,
		reconciledState: state,
	}
}

func TestKustomizationReconciler_Reconcile_OCIFetchResults(t *testing.T) {
	tests := []struct {
		name     string
		fetchErr error
	}{
		{
			name: "success",
		},
		{
			name:     "missing exporter-info layer",
			fetchErr: errors.New("exporter-info OCI layer not found"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			testOtel, err := otel.SetupTestTelemetry(ctx, "tracker-test")
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, testOtel.Shutdown(context.Background())) })
			trackerMetrics, err := NewMetrics(testOtel.MeterProvider.Meter(InstrumentationScope))
			require.NoError(t, err)

			namespace := "test-ns"
			sourceName := "kube-manifests-oci"
			ociRevision := "master@sha256:6971561bf3f0adf0ae0059420b3778302e4c8e44e2ed27bd9acc900b3a7ed45e"
			timeApplied := time.Date(2026, 9, 15, 22, 51, 49, 0, time.UTC)
			dtCommitTime := timeApplied.Add(-15 * time.Minute)
			pushStartTime := timeApplied.Add(-90 * time.Second)

			kustomization := makeOCIKustomizationObject(namespace, "test-kustomization-oci", namespace, sourceName, ociRevision, timeApplied)
			ociRepository := makeOCIRepositoryObject(namespace, sourceName, "oci://ghcr.io/grafana/kube-manifests")
			fakeK8sClient := fake.NewClientBuilder().
				WithScheme(setupScheme(t)).
				WithObjects(kustomization, ociRepository).
				Build()

			fakeOCI := &fakeOCIResolver{
				FetchErr: tt.fetchErr,
				ArtifactInfo: oci.ArtifactInfo{
					PushStartTime: pushStartTime,
					ExporterInfo: oci.ExporterInfo{
						CommitsSinceLastExport: []*oci.CommitInfo{
							{
								Hash: "fedcba654321",
								Time: dtCommitTime,
							},
						},
					},
				},
			}
			reconciler := &KustomizationReconciler{
				Client:  fakeK8sClient,
				Log:     slog.Default(),
				OCI:     fakeOCI,
				Metrics: trackerMetrics,
			}

			req := makeMeasurementRequest(t, kustomization)
			result, reconcileErr := reconciler.Reconcile(ctx, req)
			require.Equal(t, ctrl.Result{}, result)
			require.Equal(t, []string{ociRevision}, fakeOCI.Revisions)

			metrics, err := testOtel.ForceMetricCollection(ctx)
			require.NoError(t, err)
			if tt.fetchErr != nil {
				require.ErrorIs(t, reconcileErr, tt.fetchErr)
				require.Nil(t, otel.FindMetric(metrics, MetricE2EExportTime))
				require.Nil(t, otel.FindMetric(metrics, MetricOCIPushToApplyTime))
				return
			}

			require.NoError(t, reconcileErr)
			otel.AssertHistogramValue(t, metrics, MetricE2EExportTime, timeApplied.Sub(dtCommitTime).Seconds())
			otel.AssertHistogramValue(t, metrics, MetricOCIPushToApplyTime, timeApplied.Sub(pushStartTime).Seconds())
		})
	}
}

func TestKustomizationReconciler_Reconcile_UsesOriginalRevisionAndTimestamp(t *testing.T) {
	tests := []struct {
		name          string
		retry         bool
		wantRevisions []string
	}{
		{
			name:          "delayed processing",
			wantRevisions: []string{"revision-B"},
		},
		{
			name:          "OCI failure then retry",
			retry:         true,
			wantRevisions: []string{"revision-B", "revision-B"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testOtel, err := otel.SetupTestTelemetry(t.Context(), "tracker-test")
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, testOtel.Shutdown(context.Background())) })
			trackerMetrics, err := NewMetrics(testOtel.MeterProvider.Meter(InstrumentationScope))
			require.NoError(t, err)

			timeApplied := time.Date(2026, 9, 15, 22, 51, 49, 0, time.UTC)
			kustomization := makeOCIKustomizationObject("test-ns", "test", "test-ns", "source", "revision-B", timeApplied)
			req := makeMeasurementRequest(t, kustomization)

			ociRepository := makeOCIRepositoryObject("test-ns", "source", "oci://example.com/manifests")
			fakeK8sClient := fake.NewClientBuilder().
				WithScheme(setupScheme(t)).
				WithStatusSubresource(kustomization).
				WithObjects(kustomization, ociRepository).
				Build()

			fakeOCI := &fakeOCIResolver{
				ArtifactInfo: oci.ArtifactInfo{
					PushStartTime: timeApplied.Add(-10 * time.Second),
					ExporterInfo: oci.ExporterInfo{
						CommitsSinceLastExport: []*oci.CommitInfo{
							{
								Hash: "commit",
								Time: timeApplied.Add(-290 * time.Second),
							},
						},
					},
				},
			}

			reconciler := &KustomizationReconciler{
				Client:  fakeK8sClient,
				Log:     slog.Default(),
				OCI:     fakeOCI,
				Metrics: trackerMetrics,
			}

			if tt.retry {
				fakeOCI.FetchErr = errors.New("registry unavailable")
				_, err := reconciler.Reconcile(t.Context(), req)
				require.ErrorContains(t, err, "registry unavailable")

				fakeOCI.FetchErr = nil
			}

			// Flux applies a newer revision before we finish measuring the previous one
			kustomization.Status.LastAppliedRevision = "revision-C"
			kustomization.Status.Conditions[0].LastTransitionTime = metav1.NewTime(timeApplied.Add(11 * time.Hour))
			require.NoError(t, fakeK8sClient.Status().Update(t.Context(), kustomization))

			_, err = reconciler.Reconcile(t.Context(), req)
			require.NoError(t, err)
			require.Equal(t, tt.wantRevisions, fakeOCI.Revisions)

			metrics, err := testOtel.ForceMetricCollection(t.Context())
			require.NoError(t, err)
			otel.AssertHistogramValue(t, metrics, MetricE2EExportTime, 290)
			otel.AssertHistogramValue(t, metrics, MetricOCIPushToApplyTime, 10)
		})
	}
}

func TestExtractReconciledState_WithoutSuccessfulTimestamp(t *testing.T) {
	tests := []struct {
		name   string
		status metav1.ConditionStatus
	}{
		{
			name:   "Ready is false",
			status: metav1.ConditionFalse,
		},
		{
			name:   "Ready is unknown",
			status: metav1.ConditionUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kustomization := makeOCIKustomizationObject("test-ns", "test", "test-ns", "source", "revision-B", time.Now())
			kustomization.Status.Conditions[0].Status = tt.status
			kustomization.Status.Conditions[0].Reason = "Progressing"
			_, err := extractReconciledState(kustomization)
			require.ErrorContains(t, err, "has not reconciled successfully yet")
		})
	}
}
