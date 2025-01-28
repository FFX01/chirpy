package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(pw string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), 12)
	if err != nil {
		return "", fmt.Errorf("Can not hash password")
	}
	hashAsString := string(hash)
	return hashAsString, nil
}

func CheckPasswordHash(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

func MakeJWT(userID uuid.UUID, secret string, ttl time.Duration) (string, error) {
	now := time.Now().UTC()
	claims := jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		Subject:   userID.String(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}
	return signedToken, nil
}

func ValidateJWT(tokenString, secret string) (uuid.UUID, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	if err != nil {
		return uuid.UUID{}, err
	}
	userID, err := token.Claims.GetSubject()
	if err != nil {
		return uuid.UUID{}, err
	}
	userIDAsUUID, err := uuid.Parse(userID)
	if err != nil {
		return uuid.UUID{}, err
	}
	return userIDAsUUID, nil
}

func GetBearerToken(headers http.Header) (string, error) {
	h := headers.Get("Authorization")
	if h == "" {
		return "", errors.New("Missing Authorization Header")
	}
	splitHeader := strings.Split(h, " ")
	if len(splitHeader) != 2 {
		return "", errors.New("Malformed Authorization header")
	}
	if splitHeader[0] != "Bearer" {
		return "", errors.New("Malformed Authorization header")
	}

	return splitHeader[1], nil
}

func MakeRefreshToken() (string, error) {
	data := make([]byte, 32)
	_, err := rand.Read(data)
	if err != nil {
		return "", err
	}
	encoded := hex.EncodeToString(data)
	return encoded, nil
}

func GetAPIKey(headers http.Header) (string, error) {
	h := headers.Get("Authorization")
	if h == "" {
		return "", errors.New("Missing Authorization Header")
	}

	splitHeader := strings.Split(h, " ")
	if len(splitHeader) != 2 {
		return "", errors.New("Malformed Authorization header value")
	}
	if splitHeader[0] != "ApiKey" {
		return "", errors.New("Malformed Authorization header value")
	}

	return splitHeader[1], nil
}
