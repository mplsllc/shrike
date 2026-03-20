package models

import "time"

// Pagination holds pagination parameters for list queries.
type Pagination struct {
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
}

// PaginatedResult wraps a list response with pagination metadata.
type PaginatedResult[T any] struct {
	Data       []T  `json:"data"`
	Total      int  `json:"total"`
	Limit      int  `json:"limit"`
	Offset     int  `json:"offset"`
	HasMore    bool `json:"has_more"`
}

// TimeRange represents a from/to time filter.
type TimeRange struct {
	From *time.Time
	To   *time.Time
}
