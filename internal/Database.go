package internal

import (
	"database/sql"
	"log"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

func GetDatabase() *sql.DB {
	db, err := sql.Open("mysql", "root:my-secret-pw@tcp(127.0.0.1:32768)/overwatch")
	if err != nil {
		log.Fatalf("Could not create database - %s\n", err)
	}

	db.SetConnMaxIdleTime(time.Second * 20)
	return db
}
