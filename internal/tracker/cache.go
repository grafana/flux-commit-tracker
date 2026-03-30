package tracker

import (
	"time"

	"github.com/grafana/flux-commit-tracker/internal/oci"
	lru "github.com/hashicorp/golang-lru/v2/expirable"
)

const (
	exporterInfoCacheSize = 256
	exporterInfoCacheTTL  = 30 * time.Minute
)

type exporterInfoCacheKey struct {
	repositoryURL string
	revision      string
}

func newExporterInfoCache() *lru.LRU[exporterInfoCacheKey, oci.ExporterInfo] {
	return lru.NewLRU[exporterInfoCacheKey, oci.ExporterInfo](exporterInfoCacheSize, nil, exporterInfoCacheTTL)
}
