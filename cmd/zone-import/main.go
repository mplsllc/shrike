package main

import (
	"log"

	"git.mp.ls/mpls/shrike/internal/version"
)

func main() {
	log.Printf("Shrike zone file importer %s", version.Version)
	// TODO: Implement ICANN CZDS zone file import
	log.Println("Not implemented yet")
}
