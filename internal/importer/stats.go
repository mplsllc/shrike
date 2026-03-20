package importer

// ImportStats tracks the outcome of a bulk import operation.
type ImportStats struct {
	Processed int `json:"processed"`
	Stored    int `json:"stored"`
	Unchanged int `json:"unchanged"`
	Errors    int `json:"errors"`
}

// Stats tracks the outcome of delegation/historical imports.
type Stats struct {
	IPBlocksProcessed int
	ASNsProcessed     int
}
