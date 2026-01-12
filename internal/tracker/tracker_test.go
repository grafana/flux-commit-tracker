package tracker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	kustomizev1 "github.com/fluxcd/kustomize-controller/api/v1"
	kustomizev1beta2 "github.com/fluxcd/kustomize-controller/api/v1beta2"
	"github.com/grafana/flux-commit-tracker/internal/github"
	"github.com/grafana/flux-commit-tracker/internal/otel"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// fakeGitHubClient is a fake implementation of the github.Client interface for
// testing. It returns predefined responses or errors for methods.
type fakeGitHubClient struct {
	CommitTimes   map[string]time.Time
	ExporterInfos map[string]github.ExporterInfo
	Files         map[string][]byte
	FetchErr      error
	GetFileErr    error
}

func (f *fakeGitHubClient) GetFile(ctx context.Context, logger *slog.Logger, repo github.GitHubRepo, path, ref string) ([]byte, error) {
	if f.GetFileErr != nil {
		return nil, f.GetFileErr
	}

	key := fmt.Sprintf("%s/%s/%s@%s", repo.Owner, repo.Repo, path, ref)
	data, ok := f.Files[key]
	if !ok {
		return nil, errors.New("fake GetFile: not found")
	}

	return data, nil
}

func (f *fakeGitHubClient) FetchCommitTime(ctx context.Context, log *slog.Logger, repo github.GitHubRepo, commitSHA string) (time.Time, error) {
	if f.FetchErr != nil {
		return time.Time{}, f.FetchErr
	}

	t, ok := f.CommitTimes[commitSHA]
	if !ok {
		return time.Time{}, fmt.Errorf("fake FetchCommitTime: commit %s not found", commitSHA)
	}

	return t, nil
}

func (f *fakeGitHubClient) FetchExporterInfo(ctx context.Context, log *slog.Logger, repo github.GitHubRepo, ref string) (github.ExporterInfo, error) {
	if f.FetchErr != nil {
		return github.ExporterInfo{}, f.FetchErr
	}

	info, ok := f.ExporterInfos[ref]
	if !ok {
		return github.ExporterInfo{}, fmt.Errorf("fake FetchExporterInfo: ref %s not found", ref)
	}

	return info, nil
}

func setupScheme(t *testing.T) *runtime.Scheme {
	t.Helper()

	scheme := runtime.NewScheme()
	err := kustomizev1.AddToScheme(scheme)

	require.NoError(t, err)

	return scheme
}

func TestKustomizationReconciler_Reconcile_Success(t *testing.T) {
	ctx := t.Context()
	testOtel, err := otel.SetupTestTelemetry(ctx, "test-service")
	require.NoError(t, err)
	defer func() { _ = testOtel.Shutdown(ctx) }()

	scheme := setupScheme(t)
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	namespace := "test-ns"
	name := "test-kustomization"
	kubeManifestsHash := "abcdef123456"
	reconciledRevision := "main@sha1:" + kubeManifestsHash
	dtCommitHash := "fedcba654321"

	// The Kubernetes `metaV1.Time` type is an RFC3339 string, which is only
	// accurate to the second. If we use nanosecond precision, when we try to
	// compare back at the end we'll fail due to this precision loss.
	timeApplied := time.Now().Add(-5 * time.Minute).Truncate(time.Second)
	kubeManifestsCommitTime := timeApplied.Add(-10 * time.Minute).Truncate(time.Second)
	dtCommitTime := kubeManifestsCommitTime.Add(-15 * time.Minute).Truncate(time.Second)

	kustomization := &kustomizev1.Kustomization{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			UID:       types.UID("test-uid"),
		},
		Status: kustomizev1.KustomizationStatus{
			LastAppliedRevision: reconciledRevision,
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

	exporterInfo := github.ExporterInfo{
		CommitsSinceLastExport: []*github.CommitInfo{
			{Hash: dtCommitHash, Time: dtCommitTime},
		},
	}

	fakeGH := &fakeGitHubClient{
		CommitTimes: map[string]time.Time{
			kubeManifestsHash: kubeManifestsCommitTime,
		},
		ExporterInfos: map[string]github.ExporterInfo{
			kubeManifestsHash: exporterInfo,
		},
	}

	fakeK8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(kustomization).Build()

	reconciler := &KustomizationReconciler{
		Client: fakeK8sClient,
		Scheme: scheme,
		Log:    log,
		GitHub: fakeGH,
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

	// Verify metrics
	metrics, err := testOtel.ForceMetricCollection(ctx)
	require.NoError(t, err)

	// Time from `kube-manifests` commit to `flux apply`
	otel.AssertMetricValueExists(t, metrics, MetricFluxReconcileTime)
	// Time from `deployment-tools` commit to `flux apply`
	otel.AssertMetricValueExists(t, metrics, MetricE2EExportTime)
	// Time from `deployment-tools` commit to `kube-manifests` commit
	otel.AssertMetricValueExists(t, metrics, MetricKubeManifestsExporterExportTime)

	expectedFluxReconcileTime := timeApplied.Sub(kubeManifestsCommitTime).Seconds()
	expectedKubeManifestsExporterTime := kubeManifestsCommitTime.Sub(dtCommitTime).Seconds()
	expectedE2ETime := timeApplied.Sub(dtCommitTime).Seconds()

	// Verify metric values
	otel.AssertHistogramValue(t, metrics, MetricFluxReconcileTime, expectedFluxReconcileTime)
	otel.AssertHistogramValue(t, metrics, MetricKubeManifestsExporterExportTime, expectedKubeManifestsExporterTime)
	otel.AssertHistogramValue(t, metrics, MetricE2EExportTime, expectedE2ETime)
}

// TestKustomizationReconciler_Reconcile_OCIRepository_Success tests that OCIRepository
// sources correctly extract the kube-manifests hash from LastAppliedOriginRevision
// (which comes from the org.opencontainers.image.revision OCI annotation).
func TestKustomizationReconciler_Reconcile_OCIRepository_Success(t *testing.T) {
	scheme := setupScheme(t)
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	namespace := "test-ns"
	name := "test-kustomization-oci"
	kubeManifestsHash := "7fffb7d913b054f730376425dd9360fdc1647140"
	ociRevision := "master@sha256:6971561bf3f0adf0ae0059420b3778302e4c8e44e2ed27bd9acc900b3a7ed45e"
	dtCommitHash := "fedcba654321"

	timeApplied := time.Now().Add(-5 * time.Minute).Truncate(time.Second)
	kubeManifestsCommitTime := timeApplied.Add(-10 * time.Minute).Truncate(time.Second)
	dtCommitTime := kubeManifestsCommitTime.Add(-15 * time.Minute).Truncate(time.Second)

	kustomization := &kustomizev1.Kustomization{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			UID:       types.UID("test-uid-oci"),
		},
		Spec: kustomizev1.KustomizationSpec{
			SourceRef: kustomizev1.CrossNamespaceSourceReference{
				Kind: "OCIRepository",
				Name: "kube-manifests-oci",
			},
		},
		Status: kustomizev1.KustomizationStatus{
			LastAppliedRevision: ociRevision,
			// LastAppliedOriginRevision contains the kube-manifests commit SHA
			// from the org.opencontainers.image.revision OCI annotation
			LastAppliedOriginRevision: kubeManifestsHash,
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

	exporterInfo := github.ExporterInfo{
		CommitsSinceLastExport: []*github.CommitInfo{
			{Hash: dtCommitHash, Time: dtCommitTime},
		},
	}

	fakeGH := &fakeGitHubClient{
		CommitTimes: map[string]time.Time{
			kubeManifestsHash: kubeManifestsCommitTime,
		},
		ExporterInfos: map[string]github.ExporterInfo{
			kubeManifestsHash: exporterInfo,
		},
	}

	fakeK8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(kustomization).Build()

	reconciler := &KustomizationReconciler{
		Client: fakeK8sClient,
		Scheme: scheme,
		Log:    log,
		GitHub: fakeGH,
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

func TestKustomizationReconciler_Reconcile_KustomizationNotFound(t *testing.T) {
	scheme := setupScheme(t)
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError})) // Use Error level to avoid noise

	namespace := "test-ns"
	name := "non-existent-kustomization"

	fakeGH := &fakeGitHubClient{}

	fakeK8sClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	reconciler := &KustomizationReconciler{
		Client: fakeK8sClient,
		Scheme: scheme,
		Log:    log,
		GitHub: fakeGH,
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
	kubeManifestsHash := "abcdef123456"
	reconciledRevision := "main@sha1:" + kubeManifestsHash
	timeApplied := time.Now() // Reconciliation time doesn't matter here

	// Kustomization exists but has no successful reconciliation condition
	kustomization := &kustomizev1.Kustomization{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			UID:       types.UID("test-uid-pending"),
		},
		Status: kustomizev1.KustomizationStatus{
			LastAppliedRevision: reconciledRevision,
			Conditions: []metav1.Condition{
				{
					Type:               "Ready",
					Status:             metav1.ConditionFalse, // Not True
					Reason:             "Progressing",         // Not ReconciliationSucceededReason
					LastTransitionTime: metav1.Time{Time: timeApplied},
				},
			},
		},
	}

	fakeGH := &fakeGitHubClient{}

	fakeK8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(kustomization).Build()

	reconciler := &KustomizationReconciler{
		Client: fakeK8sClient,
		Scheme: scheme,
		Log:    log,
		GitHub: fakeGH,
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      name,
			Namespace: namespace,
		},
	}
	result, err := reconciler.Reconcile(t.Context(), req)

	require.Error(t, err)
	expectedErr := fmt.Sprintf("kustomization '%s/%s' has not reconciled successfully yet", namespace, name)
	require.EqualError(t, err, expectedErr)
	require.Equal(t, ctrl.Result{}, result)
}
