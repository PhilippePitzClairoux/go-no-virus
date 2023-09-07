package configuration

import "testing"

func TestLoadApplicationConfiguration(t *testing.T) {
	_, err := LoadApplicationConfiguration("./valid_test.yaml")
	if err != nil {
		t.Error("could not parse configuration file")
	}

	t.Log("configuration was loaded and parsed successfully")
}

func TestLoadApplicationConfigurationBadConfigFile(t *testing.T) {
	_, err := LoadApplicationConfiguration("./invalid-config.yaml")
	if err != nil {
		t.Log("there was an error parsing the config file - which is normal since it doesn't exist")
		return
	}

	t.Error("file was parsed without any errors and yet it should.")
}
