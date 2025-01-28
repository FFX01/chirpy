package auth

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func TestHashPassword(t *testing.T) {
	var tests = []string{
		"mypass%%wo@rd",
		"otherpa!ssword",
		"anotherp*(assw0rd",
	}

	for _, tt := range tests {
		testname := fmt.Sprintf("TestHashPassword password %s", tt)
		t.Run(testname, func(t *testing.T) {
			hash, err := HashPassword(tt)
			if err != nil {
				t.Errorf("Expected no errors, but triggered error: %s", err.Error())
			}
			cost, err := bcrypt.Cost([]byte(hash))
			if err != nil {
				t.Errorf("Unexpected error: %s", err.Error())
			}
			if cost != 12 {
				t.Errorf("Expected cost of 12, but got: %d", cost)
			}
		})
	}
}

func TestCheckPasswordHash(t *testing.T) {
	type testSchema struct {
		password string
		hash     string
	}
	var passwords = []string{
		"foob^&ar",
		"wo#$lolo",
		"herp*()aderpa",
	}
	var tests = []testSchema{}
	for _, pw := range passwords {
		hash, err := HashPassword(pw)
		if err != nil {
			t.Errorf("Unexpected error: %s", err.Error())
		}
		st := testSchema{
			password: pw,
			hash:     hash,
		}
		tests = append(tests, st)
	}

	for _, tt := range tests {
		err := CheckPasswordHash(tt.password, tt.hash)
		if err != nil {
			t.Errorf("CheckPasswordHash returned error: %s", err.Error())
		}
	}
}

func TestMakeJWT(t *testing.T) {
	var tests = []struct {
		userID uuid.UUID
		secret string
		ttl    time.Duration
	}{
		{userID: uuid.New(), secret: "secret", ttl: 3 * time.Hour},
		{userID: uuid.New(), secret: "secret", ttl: 10 * time.Minute},
		{userID: uuid.New(), secret: "othersecret", ttl: 24 * time.Hour},
	}

	for _, tt := range tests {
		jwt, err := MakeJWT(tt.userID, tt.secret, tt.ttl)
		if err != nil {
			t.Errorf("Unexpected error: %s", err.Error())
		}
		if len(jwt) < 1 {
			t.Errorf("JWT is empty")
		}
	}
}

func TestValidateJWT(t *testing.T) {
	secret := "supersecret"
	var tests = []string{}
	for range 3 {
		token, err := MakeJWT(uuid.New(), secret, 24*time.Hour)
		if err != nil {
			t.Errorf("Unable to create tokens: %s", err.Error())
		}
		tests = append(tests, token)
	}

	for _, tt := range tests {
		userID, err := ValidateJWT(tt, secret)
		if err != nil {
			t.Errorf("Error validating token: %s", err.Error())
		}
		if len(userID) < 1 {
			t.Errorf("Expected user id to have a length greater than 1")
		}
	}
}

func TestValidateJWTTTL(t *testing.T) {
	secret := "supersecret"
	var tests = []struct {
		Subject uuid.UUID
		TTL     time.Duration
	}{
		{Subject: uuid.New(), TTL: 1 * time.Second},
		{Subject: uuid.New(), TTL: 3 * time.Second},
		{Subject: uuid.New(), TTL: 1 * time.Hour},
	}
	var tokens []string
	for _, tt := range tests {
		token, err := MakeJWT(tt.Subject, secret, tt.TTL)
		if err != nil {
			t.Errorf("Error creating token: %s", err.Error())
		}
		tokens = append(tokens, token)
	}
	time.Sleep(3 * time.Second)
	_, err := ValidateJWT(tokens[0], secret)
	if err == nil {
		t.Error("Token should be invalid but got valid")
	}
	_, err = ValidateJWT(tokens[1], secret)
	if err == nil {
		t.Error("Token should be invalid but got valid")
	}
	_, err = ValidateJWT(tokens[2], secret)
	if err != nil {
		t.Error("Token should be valid, but got invalid")
	}
}

func TestValidateJWTSecret(t *testing.T) {
	secret := "supersecret"
	var tests = []struct {
		Subject uuid.UUID
		secret  string
	}{
		{Subject: uuid.New(), secret: "glorpglop"},
		{Subject: uuid.New(), secret: "foobar"},
		{Subject: uuid.New(), secret: "herpaderpa"},
	}
	for _, tt := range tests {
		token, err := MakeJWT(tt.Subject, secret, 1*time.Hour)
		if err != nil {
			t.Error("Unable to create token")
		}
		_, err = ValidateJWT(token, tt.secret)
		if err == nil {
			t.Error("Token should be invalid but it is valid")
		}
	}
}

func TestGetBearerToken(t *testing.T) {
	var badTests = []string{
		"Boots 12345",
		"12345",
		"gobblydeegoock",
	}

	for _, tt := range badTests {
		headers := http.Header{
			"Authorization": {tt},
		}
		_, err := GetBearerToken(headers)
		if err == nil {
			t.Error("Expected error, but received none")
		}
	}

	var goodTests = []string{
		"Bearer 12345",
		"Bearer foobar",
		"Bearer herpaderpa",
	}

	for _, tt := range goodTests {
		headers := http.Header{
			"Authorization": {tt},
		}
		token, err := GetBearerToken(headers)
		if err != nil {
			t.Error(err.Error())
		}
		if token == "" {
			t.Error("Expected token but got empty string")
		}
	}
}

func TestMakeRefreshToken(t *testing.T) {
    for range 5 {
        token, err := MakeRefreshToken()
        if err != nil {
            t.Error("Error generating refresh token")
        }
        if len(token) < 32 {
            t.Errorf("Expected 32 length, got: %s", token)
        }
    }
}
