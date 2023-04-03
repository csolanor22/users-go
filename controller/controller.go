package controller

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"time"
	"users/model"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-playground/validator/v10"
	"gorm.io/gorm"
)

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

var JwtKey = []byte("Y29kaWdvIHNlY3JldG8gcGFyYSBsYSBnZW5lcmFjaW9uIGRlbCBqd3Q=")

func CreateUser(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var user model.User
		var newUser model.NewUserRequest
		var response model.NewUserCreated

		json.NewDecoder(r.Body).Decode(&newUser)

		validate := validator.New()
		err := validate.Struct(newUser)
		if err != nil {
			w.Header().Add("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		result := db.Table("users").Where("username = ? OR email = ?", newUser.Username, newUser.Email).Find(&user)

		if result.RowsAffected != 0 {
			w.WriteHeader(412)
			return
		}

		var salt = randSeq(10)

		var password = hashPassword(newUser.Password, salt)

		user.CreatedAt = time.Now()
		user.Username = newUser.Username
		user.Password = password
		user.Email = newUser.Email
		user.Salt = salt
		user.ExpireAt = time.Now()

		db.Create(&user).Scan(&user)

		response.Id = user.Id
		response.CreatedAt = user.CreatedAt

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(&response)

	}
}

func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

// Combine password and salt then hash them using the SHA-512
// hashing algorithm and then return the hashed password
// as a hex string
func hashPassword(password string, salt string) string {
	// Convert password string to byte slice
	var passwordBytes = []byte(password)
	var saltGenerated = []byte(salt)

	// Create sha-512 hasher
	var sha512Hasher = sha512.New()

	// Append salt to password
	passwordBytes = append(passwordBytes, saltGenerated...)

	// Write password bytes to the hasher
	sha512Hasher.Write(passwordBytes)

	// Get the SHA-512 hashed password
	var hashedPasswordBytes = sha512Hasher.Sum(nil)

	// Convert the hashed password to a hex string
	var hashedPasswordHex = hex.EncodeToString(hashedPasswordBytes)

	return hashedPasswordHex
}

func GetToken(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var getTokenRq model.GetTokenRq
		var user model.User
		var getTokenRs model.GetTokenRs

		json.NewDecoder(r.Body).Decode(&getTokenRq)

		validate := validator.New()
		err := validate.Struct(getTokenRq)
		if err != nil {
			w.Header().Add("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		result := db.Table("users").Where("username = ?", getTokenRq.Username).Find(&user)

		if result.RowsAffected == 0 {
			w.WriteHeader(404)
			return
		}

		if !doPasswordsMatch(user.Password, getTokenRq.Password, user.Salt) {
			w.WriteHeader(404)
			return
		}

		var expireAt = time.Now().Add(time.Hour * time.Duration(1)).Unix()

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"username": user.Username,
			"id":       user.Id,
			"email":    user.Email,
			"exp":      expireAt,
		})
		tokenString, error := token.SignedString(JwtKey)
		if error != nil {
			fmt.Println(error)
		}

		user.ExpireAt = time.Unix(expireAt, 0)
		user.Token = tokenString
		db.Save(&user)

		getTokenRs.Token = tokenString
		getTokenRs.Id = user.Id
		getTokenRs.ExpireAt = time.Unix(expireAt, 0)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(&getTokenRs)
	}
}

// Check if two passwords match
func doPasswordsMatch(hashedPassword, currPassword string, salt string) bool {
	var currPasswordHash = hashPassword(currPassword, salt)
	return hashedPassword == currPasswordHash
}

func VerifyToken(w http.ResponseWriter, r *http.Request) {
	authorizationHeader := r.Header.Get("Authorization")
	var VerifyTokenRs model.VerifyTokenRs

	if authorizationHeader != "" {
		bearerToken := strings.Split(authorizationHeader, " ")
		if len(bearerToken) == 2 {
			token, error := jwt.Parse(bearerToken[1], func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("There was an error")
				}
				return JwtKey, nil
			})
			if error != nil && !token.Valid {
				w.WriteHeader(401)
				return
			}
			bearerTokenData := strings.Split(bearerToken[1], ".")
			rawDecodedText, err := base64.RawStdEncoding.DecodeString(bearerTokenData[1])
			if err != nil {
				panic(err)
			}
			reader := bytes.NewReader(rawDecodedText)
			w.Header().Set("Content-Type", "application/json")
			json.NewDecoder(reader).Decode(&VerifyTokenRs)
			json.NewEncoder(w).Encode(&VerifyTokenRs)
		}
	} else {
		w.WriteHeader(400)
		return
	}

}

func Ping(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(200)
	w.Write([]byte("Pong"))
}
