package rand

import (
	"crypto/rand"
	"encoding/base64"
)

const RemeberTokenBytes = 32

// RememberToken is a helper function designed to generate
// remember tokens of a predetermined byte size.
func RememberToken() (string, error) {
	return String(RemeberTokenBytes)
}

// Bytes will help us generate n random bytes, or will 
// return an error if there was one. This uses the crypto/rand
// package so it is safe to use with things like remember tokens.
func Bytes(n int) ([]byte, error) {
	// Create a byte slice of equal length to the value of n
	b := make([]byte, n)
	// Call the Read func, check for errors, and 
	// return byte slice if no errors. 	
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// String will generate a byte slice of size nBytes and then
// return a string that is the base64 URL encoded version
// of that byte slice.
func String(nBytes int) (string, error) {
	b, err := Bytes(nBytes)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

