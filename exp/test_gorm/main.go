package main

import (
	"fmt"
	
	"github.com/jinzhu/gorm"
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
// Connecting to database
	us, err := models.NewUserService(psqlInfo)
	if err != nil {
		panic(err)
	}
// Defer close and destroy/rebuild database.	
	defer us.Close()
	us.DestructiveReset
// 	Lookup user with id of 1. 
	user, err := us.ByID(1)
	if err != nil {
		panic(err)
	}
// 	Print user to console.
	fmt.Println(user)
}