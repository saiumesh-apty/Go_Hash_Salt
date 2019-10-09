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
	"time"

	"golang.org/x/crypto/argon2"
)

// source https://godoc.org/golang.org/x/crypto/argon2

const (
	PasswordType = "AptyID"
	SaltLength   = 32
	Time         = 1
	Memory       = 64 * 1024
	KeyLen       = 32
	Threads      = 10
)

func generateSalt(len int) (string, error) {
	unencodedSalt := make([]byte, len)
	if _, err := rand.Read(unencodedSalt); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(unencodedSalt), nil
}

func generateSaltedHash(password, salt string) (string, error) {
	cryptoKey := argon2.IDKey([]byte(password), []byte(salt), Time, Memory, uint8(Threads), KeyLen)
	encodedPassword := base64.StdEncoding.EncodeToString(cryptoKey)
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
	default:
		return false, errors.New("Invalid Password Hash")
	}

	if subtle.ConstantTimeCompare(key, calculatedKey) != 1 {
		return false, errors.New("Password did not match")
	}
	return true, nil

}

func main() {

	fmt.Println("runTime", runtime.NumCPU())

	totalTime := time.Now()

	saltTime := time.Now()

	passwordSalt, err := generateSalt(SaltLength)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("saltTime", time.Since(saltTime))

	hashTime := time.Now()
	hashedPassword, err := generateSaltedHash("SaltLength", passwordSalt)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("hashTime", time.Since(hashTime))
	fmt.Println(hashedPassword)

	compareTime := time.Now()

	isPasswordEqual, err := CompareHashWithPassword(hashedPassword, "SaltLength", passwordSalt)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("compareTime", time.Since(compareTime))
	fmt.Println("totalTime", time.Since(totalTime))
	fmt.Println(isPasswordEqual) // True

	// wrong password
	_, err = CompareHashWithPassword(hashedPassword, "SaltLength", "passwordSalt")
	if err != nil {
		log.Fatal(err.Error()) // wrong password error
	}
}
