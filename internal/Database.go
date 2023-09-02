package internal

import (
	"database/sql"
	"log"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func init() {
	log.Println("connecting/creating database...")
	db := GetDatabase()

	defer db.Close()
	_, err := db.Exec(`
	PRAGMA journal_mode=WAL; -- write-Ahead Logging Mode
	PRAGMA busy_timeout = 20000; -- set timeout to 10 seconds

	CREATE TABLE IF NOT EXISTS file_monitoring (
	    path VARCHAR(2048) NOT NULL,
	    hash VARCHAR(255) NOT NULL,
	    inserted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, 
	    PRIMARY KEY (path, hash)
	);

	CREATE TABLE IF NOT EXISTS file_monitoring_conflicts (
		path VARCHAR(2048) NOT NULL,
		new_hash VARCHAR(255),
		old_hash VARCHAR(255),
		checked boolean DEFAULT false
	);
	
	CREATE TABLE IF NOT EXISTS suspicious_process (
	  inserted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	  pid INT NOT NULL,
	  cmd_line VARCHAR,
	  suspicious_connection VARCHAR
	);

	CREATE TABLE IF NOT EXISTS virus_detected (
	    inserted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	    path VARCHAR(2048) NOT NULL,
	    cause VARCHAR(255) NOT NULL,
	    PRIMARY KEY (path, cause)
	)
`)
	if err != nil {
		log.Fatalf("Could not create table - %s\n", err)
	}

}

func GetDatabase() *sql.DB {
	db, err := sql.Open("sqlite3", "./overwatch.db")
	if err != nil {
		log.Fatalf("Could not create database - %s\n", err)
	}

	db.SetConnMaxIdleTime(time.Second * 20)
	return db
}
