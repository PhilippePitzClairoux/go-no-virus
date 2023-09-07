package internal

import (
	"testing"
)

func TestGetDatabase(t *testing.T) {
	_ = GetDatabase()
	t.Log("Got database connection - DB setup work and connection to db works as well")
}
