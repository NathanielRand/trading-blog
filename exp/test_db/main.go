package main

import (
	"database/sql"
	"fmt"
	
	_ "github.com/lib/pq"
)

const (
	host = "localhost"
	port = 5432
	user = "postgres"
	password = "temppassword"
	dbname = "priva_dev"
)

func main() {
// 	Creating the connection string.
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s "+
    "password=%s dbname=%s sslmode=disable",
    host, port, user, password, dbname)
// 	Opening a database connection.
	db, err := sql.Open("postgres", psqlInfo)
	if err != nil {
		panic(err)
	}
// 	Pinging the database.
	err = db.Ping()
	if err != nil {
		panic(err)
	}
// 	Print success/error message.
	fmt.Println("Successfully connected!")
// 	Close database connection.
	db.Close()
}