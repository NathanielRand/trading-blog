package main

import (
	"fmt"
	
	"priva-web/rand"
	"priva-web/hash"
)

func main() {
	fmt.Println(rand.String(10))
	fmt.Println(rand.RememberToken())
	
	hmac := hash.NewHMAC("my-secret-key")
	//	This should print out:
 	//	4waUFc1cnuxoM2oUOJfpGZLGP1asj35y7teuweSFgPY=
	fmt.Println(hmac.Hash("this is my string to hash"))
}