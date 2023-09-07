package tasks

import (
	"endpointSecurityAgent/internal"
	"endpointSecurityAgent/pkg/goclam"
	"log"
)

func virusDetected(report goclam.ClEngineFileReport) error {
	log.Printf("%s %s %s (%d bytes)\n", report.Path, report.ClEngineFlagRaised, report.ClEngineError, report.BytesScanned)
	db := internal.GetDatabase()
	defer db.Close()

	_, err := db.Exec("INSERT OR IGNORE INTO virus_detected(path, cause) VALUES (?, ?)", report.Path, report.ClEngineFlagRaised)
	return err
}
