package tracker

import (
	"fmt"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/grafana/flux-commit-tracker/internal/oci"
)

const exporterInfoCacheSize = 256

type exporterInfoCacheKey struct {
	repositoryURL string
	revision      string
}

func newExporterInfoCache() *lru.Cache[exporterInfoCacheKey, oci.ExporterInfo] {
	cache, err := lru.New[exporterInfoCacheKey, oci.ExporterInfo](exporterInfoCacheSize)
	if err != nil {
		panic(fmt.Sprintf("failed to create exporter-info cache: %v", err))
	}

	return cache
}
