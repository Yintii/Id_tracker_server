package main

import (
	"fmt"
	"os"

	"golang.org/x/crypto/bcrypt"
)

func hash() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run hash.go <password>")
		return
	}

	password := os.Args[1]
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		fmt.Println("error hashing password:", err)
		return
	}

	fmt.Println("Hashed password:", string(hash))
}
