package internal

import (
	"database/sql"
	"errors"
	"log"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

type QueryHolder struct {
	Query    string
	Args     []interface{}
	RowCount int
}

func SelectData(query QueryHolder) ([][]string, error) {
	db := getDatabaseConnection()
	defer handleClosable(db)

	rows, err := db.Query(
		query.Query,
		query.Args...,
	)
	if err != nil {
		return nil, err
	}

	var one, two, three string
	var result [][]string
	defer handleClosable(rows)

	for rows.Next() {
		switch query.RowCount {
		case 1:
			one, err = scanOne(rows)
			result = append(result, []string{one})
		case 2:
			one, two, err = scanTwo(rows)
			result = append(result, []string{one, two})
		case 3:
			one, two, three, err = scanThree(rows)
			result = append(result, []string{one, two, three})
		default:
			err = errors.New("invalid row count supplied")
		}

		if err != nil {
			return nil, err
		}

	}

	return result, nil
}

func ExecuteQuery(holder QueryHolder) (sql.Result, error) {
	db := getDatabaseConnection()
	defer handleClosable(db)

	return db.Exec(holder.Query, holder.Args...)
}

func scanOne(row *sql.Rows) (string, error) {
	var one string
	err := row.Scan(one)
	if err != nil {
		return "", err
	}
	return one, nil
}

func scanTwo(row *sql.Rows) (string, string, error) {
	var one, two string
	err := row.Scan(one, two)
	if err != nil {
		return "", "", err
	}
	return one, two, nil
}

func scanThree(row *sql.Rows) (string, string, string, error) {
	var one, two, three string
	err := row.Scan(one, two, three)
	if err != nil {
		return "", "", "", err
	}
	return one, two, three, nil
}

func getDatabaseConnection() *sql.DB {
	db, err := sql.Open("mysql", "root:my-secret-pw@tcp(127.0.0.1:3306)/overwatch")
	if err != nil {
		log.Fatalf("Could not create database - %s\n", err)
	}

	db.SetConnMaxIdleTime(time.Second * 5)
	db.SetMaxIdleConns(1)

	return db
}

type closableConnection interface {
	Close() error
}

func handleClosable(cc closableConnection) {
	err := cc.Close()
	if err != nil {
		log.Println("could not close database connection properly : ", err)
	}
}
