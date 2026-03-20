package models

import "time"

type Organization struct {
	ID             int64     `json:"id"`
	Name           string    `json:"name"`
	NameNormalized string    `json:"name_normalized"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}
