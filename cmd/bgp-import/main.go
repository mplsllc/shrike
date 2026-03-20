package main

import (
	"log"

	"git.mp.ls/mpls/shrike/internal/version"
)

func main() {
	log.Printf("Shrike BGP importer %s", version.Version)
	// TODO: Implement RouteViews/RIPE RIS MRT import
	log.Println("Not implemented yet")
}
