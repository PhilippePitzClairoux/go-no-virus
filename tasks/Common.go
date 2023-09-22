package tasks

import (
	"endpointSecurityAgent/internal"
	"endpointSecurityAgent/pkg/goclam"
	"log"
)

func virusDetected(report goclam.ClEngineFileReport) error {
	log.Printf("%s %s %s (%d bytes)\n", report.Path, report.ClEngineFlagRaised, report.ClEngineError, report.BytesScanned)
	_, err := internal.ExecuteQuery(internal.QueryHolder{
		Query: "INSERT IGNORE INTO virus_detected(path, cause) VALUES (?, ?)",
		Args:  []interface{}{report.Path, report.ClEngineFlagRaised},
	})

	return err
}

func scanFileAndReact(path string) error {
	fileReport := goclam.ScanFile(path)

	if fileReport.HasPotentialIssue {
		err := virusDetected(fileReport)
		return err
	}
	return nil
}
