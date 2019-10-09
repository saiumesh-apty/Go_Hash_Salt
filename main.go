package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// source https://godoc.org/golang.org/x/crypto/argon2

const (
	PasswordType = "AptyID"
	SaltLength   = 32
	Time         = 1
	Memory       = 64 * 1024
	KeyLen       = 32
)

var Threads = uint8(runtime.NumCPU())

func generateSalt(len int) (string, error) {
	unencodedSalt := make([]byte, len)
	if _, err := rand.Read(unencodedSalt); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(unencodedSalt), nil
}

func generateSaltedHash(password, salt string) (string, error) {
	crypto_key := argon2.IDKey([]byte(password), []byte(salt), Time, Memory, Threads, KeyLen)
	encodedPassword := base64.StdEncoding.EncodeToString(crypto_key)
	hash := fmt.Sprintf("%s$%d$%d$%d$%d$%s$%s",
		PasswordType, Time, Memory, Threads, KeyLen, salt, encodedPassword)
	return hash, nil
}

func CompareHashWithPassword(hash, password, salt string) (bool, error) {
	hashParts := strings.Split(hash, "$")
	if len(hashParts) != 7 {
		return false, errors.New("Invalid Password Hash")
	}
	passwordType := hashParts[0]
	time, _ := strconv.Atoi((hashParts[1]))
	memory, _ := strconv.Atoi(hashParts[2])
	threads, _ := strconv.Atoi(hashParts[3])
	keyLen, _ := strconv.Atoi(hashParts[4])
	key, _ := base64.StdEncoding.DecodeString(hashParts[6])
	var calculatedKey []byte
	switch passwordType {
	case "AptyID":
		calculatedKey = argon2.IDKey([]byte(password), []byte(salt), uint32(time), uint32(memory), uint8(threads), uint32(keyLen))
	case "argon2i", "argon2":
		calculatedKey = argon2.Key([]byte(password), []byte(salt), uint32(time), uint32(memory), uint8(threads), uint32(keyLen))
	default:
		return false, errors.New("Invalid Password Hash")
	}

	if subtle.ConstantTimeCompare(key, calculatedKey) != 1 {
		return false, errors.New("Password did not match")
	}
	return true, nil

}

func main() {
	passwordSalt, err := generateSalt(SaltLength)
	if err != nil {
		log.Fatal(err)
	}
	hashedPassword, err := generateSaltedHash("SaltLength", passwordSalt)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(hashedPassword)
	isPasswordEqual, err := CompareHashWithPassword(hashedPassword, "SaltLength", passwordSalt)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(isPasswordEqual) // True

	// wrong password
	_, err = CompareHashWithPassword(hashedPassword, "SaltLenssgth", passwordSalt)
	if err != nil {
		log.Fatal(err.Error()) // wrong password error
	}
}
