package tasks

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"endpointSecurityAgent/internal"
	"errors"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type FileMonitoring struct {
	// configuration
	AllDirectories      bool     `yaml:"all_directories"`
	SpecificDirectories []string `yaml:"specific_directories"`
	ExcludedDirectories []string `yaml:"excluded_directories"`
	stopTask            bool
	stopChan            chan interface{}
}

func (t *FileMonitoring) StopChan() chan interface{} {
	if t.stopChan == nil {
		t.stopChan = make(chan interface{})
	}

	return t.stopChan
}

func (t *FileMonitoring) StopTask() {
	log.Println("STOP HAS BEEN CALLED FOR " + t.GetTaskName())
	t.stopTask = true
}

func (t *FileMonitoring) IsStopped() bool {
	return t.stopTask
}

func (t *FileMonitoring) ExecuteTask() error {
	outputChan := make(chan []string)
	errChan := make(chan error)

	go t.getFilePathsFromRootDir(outputChan, errChan)

	for {
		select {
		case err := <-errChan:
			return err
		case files := <-outputChan:
			go batchStoreFileHash(files, errChan)
		}
	}
}

func (t *FileMonitoring) GetDuration() time.Duration {
	return 5 * time.Minute
}

func (t *FileMonitoring) GetTaskName() string {
	return "FileMonitoring"
}

func (t *FileMonitoring) getFilePathsFromRootDir(out chan []string, errChan chan error) {
	var files = make([]string, 0)

	err := filepath.Walk("/", func(path string, info fs.FileInfo, err error) error {

		if t.stopTask {
			return filepath.SkipAll
		}

		if errors.Is(err, fs.ErrPermission) {
			if info != nil && info.IsDir() {
				log.Printf("Skipping directory %s - access denied", path)
				return filepath.SkipDir
			}

			return nil
		}

		if info.IsDir() && t.ignoreDirectory(path) {
			log.Printf("%s matches an ignore directory path - excluding indexing\n", path)
			return filepath.SkipDir
		}

		if info.Mode().IsRegular() {
			files = append(files, path)
		}

		if len(files) == 1000 {
			out <- files
			files = make([]string, 0)
		}

		return nil
	})

	if err != nil || t.stopTask {
		errChan <- err
		return
	}

	// send remaining files
	if len(files) > 0 {
		out <- files
	}

	errChan <- nil
}

func (t *FileMonitoring) ignoreDirectory(path string) bool {
	for _, file := range t.ExcludedDirectories {
		if strings.Contains(path, file) {
			return true
		}
	}

	return false
}

func getFileHash(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}

	defer file.Close()
	hasher := sha256.New()

	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func batchStoreFileHash(files []string, errChan chan error) {
	res, err := insertFileHash(files)
	if err != nil {
		errChan <- err
		return
	}

	if rows, _ := res.RowsAffected(); rows > 0 {
		err = searchConflict()
		if err != nil {
			errChan <- err
			return
		}
	}
}

func insertFileHash(files []string) (sql.Result, error) {
	query := `INSERT IGNORE INTO file_monitoring (path, hash) VALUES `
	var values []interface{}

	for _, file := range files {
		hash, err := getFileHash(file)
		if err != nil {
			if os.IsNotExist(err) || os.IsPermission(err) {
				continue
			} else {
				return nil, err
			}
		}

		query += "(?, ?),"
		values = append(values, file, hash)
	}

	// remove extra ,
	query = strings.TrimSuffix(query, ",")

	return internal.ExecuteQuery(internal.QueryHolder{
		Query: query,
		Args:  values,
	})
}

func searchConflict() error {
	res, err := internal.SelectData(internal.QueryHolder{
		Query: `SELECT a.path, a.hash, b.hash
					FROM file_monitoring a
					JOIN file_monitoring b
					ON a.path = b.path AND a.hash != b.hash;`,
		RowCount: 3,
	})

	if err != nil {
		return err
	}

	for _, row := range res {
		path := row[0]
		newHash := row[1]
		oldHash := row[2]

		if path != "" || newHash != "" || oldHash != "" {
			err = insertConflict(path, newHash, oldHash)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func insertConflict(path, newHash, oldHash string) error {
	_, err := internal.ExecuteQuery(internal.QueryHolder{
		Query: `INSERT INTO file_monitoring_conflicts(path, new_hash, old_hash) VALUES (?, ?, ?)`,
		Args:  []interface{}{path, newHash, oldHash},
	})

	return err
}
