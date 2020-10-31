package main

import (
	"fmt"

	"priva-web/models"

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
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s "+
		"password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)
	us, err := models.NewUserService(psqlInfo)
	if err != nil {
		panic(err)
	}
	defer us.Close()

	// This will reset the database on every run, but is fine
	// for testing things out.
	us.DestructiveReset()

	// Create a user
	user := models.User{
		Username:  "Michael Scott",
		Email: "michael@dundermifflin.com",
	}
	if err := us.Create(&user); err != nil {
		panic(err)
	}

	record := "michael@dundermifflin.com"
	
	foundUser, err := us.ByEmail(record)
	if err != nil {
		panic(err)
	}
	fmt.Println(foundUser)
}
