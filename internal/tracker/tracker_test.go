package tracker

import (
	"context"
	"errors"
	"log/slog"
	"os"
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
	ExporterInfo oci.ExporterInfo
	FetchErr     error
	FetchCalls   int
}

func (f *fakeOCIResolver) FetchExporterInfo(ctx context.Context, log *slog.Logger, repositoryURL, appliedRevision string) (oci.ExporterInfo, error) {
	f.FetchCalls++

	if f.FetchErr != nil {
		return oci.ExporterInfo{}, f.FetchErr
	}

	return f.ExporterInfo, nil
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
				Kind:      ociRepositoryKind,
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

func TestKustomizationReconciler_Reconcile_OCIRepository_Success(t *testing.T) {
	ctx := t.Context()
	testOtel, err := otel.SetupTestTelemetry(ctx, "test-service")
	require.NoError(t, err)
	defer func() { _ = testOtel.Shutdown(ctx) }()

	scheme := setupScheme(t)
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	namespace := "test-ns"
	name := "test-kustomization-oci"
	sourceName := kubeManifestsOCIRepositoryName
	ociRevision := "master@sha256:6971561bf3f0adf0ae0059420b3778302e4c8e44e2ed27bd9acc900b3a7ed45e"

	timeApplied := time.Now().Add(-5 * time.Minute).Truncate(time.Second)
	dtCommitTime := timeApplied.Add(-15 * time.Minute).Truncate(time.Second)

	kustomization := makeOCIKustomizationObject(namespace, name, namespace, sourceName, ociRevision, timeApplied)
	ociRepository := makeOCIRepositoryObject(namespace, sourceName, "oci://ghcr.io/grafana/kube-manifests")
	fakeOCI := &fakeOCIResolver{
		ExporterInfo: oci.ExporterInfo{
			CommitsSinceLastExport: []*oci.CommitInfo{
				{Hash: "fedcba654321", Time: dtCommitTime},
			},
		},
	}

	fakeK8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(kustomization, ociRepository).Build()
	reconciler := &KustomizationReconciler{
		Client:            fakeK8sClient,
		Scheme:            scheme,
		Log:               log,
		OCI:               fakeOCI,
		exporterInfoCache: newExporterInfoCache(),
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      name,
			Namespace: namespace,
		},
	}
	result, err := reconciler.Reconcile(ctx, req)
	require.NoError(t, err)
	require.Equal(t, ctrl.Result{}, result)
	require.Equal(t, 1, fakeOCI.FetchCalls)

	metrics, err := testOtel.ForceMetricCollection(ctx)
	require.NoError(t, err)

	expectedE2ETime := timeApplied.Sub(dtCommitTime).Seconds()
	otel.AssertMetricValueExists(t, metrics, MetricE2EExportTime)
	otel.AssertHistogramValue(t, metrics, MetricE2EExportTime, expectedE2ETime)
}

func TestKustomizationReconciler_Reconcile_OCIRepository_MissingExporterInfoLayer(t *testing.T) {
	ctx := t.Context()
	scheme := setupScheme(t)
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	namespace := "test-ns"
	name := "test-kustomization-oci-missing-layer"
	sourceName := kubeManifestsOCIRepositoryName
	ociRevision := "master@sha256:6971561bf3f0adf0ae0059420b3778302e4c8e44e2ed27bd9acc900b3a7ed45e"
	timeApplied := time.Now().Add(-5 * time.Minute).Truncate(time.Second)

	kustomization := makeOCIKustomizationObject(namespace, name, namespace, sourceName, ociRevision, timeApplied)
	ociRepository := makeOCIRepositoryObject(namespace, sourceName, "oci://ghcr.io/grafana/kube-manifests")
	fakeOCI := &fakeOCIResolver{FetchErr: errors.New("exporter-info OCI layer not found")}

	fakeK8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(kustomization, ociRepository).Build()
	reconciler := &KustomizationReconciler{
		Client:            fakeK8sClient,
		Scheme:            scheme,
		Log:               log,
		OCI:               fakeOCI,
		exporterInfoCache: newExporterInfoCache(),
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      name,
			Namespace: namespace,
		},
	}
	result, err := reconciler.Reconcile(ctx, req)

	require.Error(t, err)
	require.Equal(t, ctrl.Result{}, result)
	require.Equal(t, 1, fakeOCI.FetchCalls)
}

func TestKustomizationReconciler_Reconcile_IgnoresUnsupportedSourceKind(t *testing.T) {
	ctx := t.Context()
	scheme := setupScheme(t)
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	namespace := "test-ns"
	name := "test-kustomization-unsupported-source"
	revision := "main@sha1:abcdef123456"
	timeApplied := time.Now().Add(-5 * time.Minute).Truncate(time.Second)

	kustomization := &kustomizev1.Kustomization{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			UID:       types.UID("test-uid-unsupported-source"),
		},
		Spec: kustomizev1.KustomizationSpec{
			SourceRef: kustomizev1.CrossNamespaceSourceReference{
				Kind:      "Bucket",
				Name:      "test-source",
				Namespace: "flux-system",
			},
		},
		Status: kustomizev1.KustomizationStatus{
			LastAppliedRevision: revision,
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

	fakeOCI := &fakeOCIResolver{}
	fakeK8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(kustomization).Build()
	reconciler := &KustomizationReconciler{
		Client:            fakeK8sClient,
		Scheme:            scheme,
		Log:               log,
		OCI:               fakeOCI,
		exporterInfoCache: newExporterInfoCache(),
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      name,
			Namespace: namespace,
		},
	}
	result, err := reconciler.Reconcile(ctx, req)

	require.NoError(t, err)
	require.Equal(t, ctrl.Result{}, result)
	require.Equal(t, 0, fakeOCI.FetchCalls)
}

func TestKustomizationReconciler_Reconcile_KustomizationNotFound(t *testing.T) {
	scheme := setupScheme(t)
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	namespace := "test-ns"
	name := "non-existent-kustomization"

	fakeK8sClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	reconciler := &KustomizationReconciler{
		Client:            fakeK8sClient,
		Scheme:            scheme,
		Log:               log,
		OCI:               &fakeOCIResolver{},
		exporterInfoCache: newExporterInfoCache(),
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      name,
			Namespace: namespace,
		},
	}
	result, err := reconciler.Reconcile(t.Context(), req)

	require.NoError(t, err)
	require.Equal(t, ctrl.Result{}, result)
}

func TestKustomizationReconciler_Reconcile_NotYetReconciled(t *testing.T) {
	scheme := setupScheme(t)
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	namespace := "test-ns"
	name := "test-kustomization-pending"
	ociRevision := "master@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	timeApplied := time.Now()

	kustomization := &kustomizev1.Kustomization{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			UID:       types.UID("test-uid-pending"),
		},
		Spec: kustomizev1.KustomizationSpec{
			SourceRef: kustomizev1.CrossNamespaceSourceReference{
				Kind:      ociRepositoryKind,
				Name:      kubeManifestsOCIRepositoryName,
				Namespace: namespace,
			},
		},
		Status: kustomizev1.KustomizationStatus{
			LastAppliedRevision: ociRevision,
			Conditions: []metav1.Condition{
				{
					Type:               "Ready",
					Status:             metav1.ConditionFalse,
					Reason:             "Progressing",
					LastTransitionTime: metav1.Time{Time: timeApplied},
				},
			},
		},
	}

	fakeOCI := &fakeOCIResolver{}
	fakeK8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(kustomization).Build()
	reconciler := &KustomizationReconciler{
		Client:            fakeK8sClient,
		Scheme:            scheme,
		Log:               log,
		OCI:               fakeOCI,
		exporterInfoCache: newExporterInfoCache(),
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      name,
			Namespace: namespace,
		},
	}
	result, err := reconciler.Reconcile(t.Context(), req)

	require.Error(t, err)
	require.EqualError(t, err, "kustomization 'test-ns/test-kustomization-pending' has not reconciled successfully yet")
	require.Equal(t, ctrl.Result{}, result)
	require.Equal(t, 0, fakeOCI.FetchCalls)
}

func TestKustomizationReconciler_Reconcile_ReusesCachedExporterInfo(t *testing.T) {
	ctx := t.Context()
	scheme := setupScheme(t)
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	sourceNamespace := "flux-system"
	sourceName := kubeManifestsOCIRepositoryName
	ociRevision := "master@sha256:9f8e7d6c5b4a39281716f5e4d3c2b1a09876543210fedcba1234567890abcdef"
	timeApplied := time.Now().Add(-5 * time.Minute).Truncate(time.Second)
	dtCommitTime := timeApplied.Add(-15 * time.Minute).Truncate(time.Second)

	kustomizationA := makeOCIKustomizationObject("grafana", "kube-manifests-oci-grafana", sourceNamespace, sourceName, ociRevision, timeApplied)
	kustomizationB := makeOCIKustomizationObject("mimir", "kube-manifests-oci-mimir", sourceNamespace, sourceName, ociRevision, timeApplied)
	ociRepository := makeOCIRepositoryObject(sourceNamespace, sourceName, "oci://ghcr.io/grafana/kube-manifests")
	fakeOCI := &fakeOCIResolver{
		ExporterInfo: oci.ExporterInfo{
			CommitsSinceLastExport: []*oci.CommitInfo{
				{Hash: "fedcba654321", Time: dtCommitTime},
			},
		},
	}

	fakeK8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(kustomizationA, kustomizationB, ociRepository).Build()
	reconciler := &KustomizationReconciler{
		Client:            fakeK8sClient,
		Scheme:            scheme,
		Log:               log,
		OCI:               fakeOCI,
		exporterInfoCache: newExporterInfoCache(),
	}

	_, err := reconciler.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Name: kustomizationA.Name, Namespace: kustomizationA.Namespace},
	})
	require.NoError(t, err)

	_, err = reconciler.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Name: kustomizationB.Name, Namespace: kustomizationB.Namespace},
	})
	require.NoError(t, err)

	require.Equal(t, 1, fakeOCI.FetchCalls)
}
