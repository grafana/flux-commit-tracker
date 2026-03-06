package oci

import "time"

// CommitInfo holds basic information about a deployment_tools commit.
type CommitInfo struct {
	Hash    string    `json:"hash"`
	Message string    `json:"summary"`
	Author  string    `json:"author"`
	Email   string    `json:"email"`
	Time    time.Time `json:"time"`
}

// ExporterInfo matches the exporter-info payload schema.
type ExporterInfo struct {
	Commit                 string        `json:"commit"`
	CommitsSinceLastExport []*CommitInfo `json:"commits_since_last_export"`
	ExportBuildLink        string        `json:"export_build_link"`
}
