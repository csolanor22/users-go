package controller_test

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"users/controller"
	"users/model"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gorilla/mux"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func Test_CreateUser(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	gormDB, _ := gorm.Open(postgres.New(postgres.Config{
		Conn: db,
	}), &gorm.Config{})

	rows := sqlmock.NewRows([]string{"id", "username", "password", "email", "expire_at", "created_at", "token", "salt"}).
		AddRow(1, "John Doe", "e0d803e4f6bd9621e2bf87b359c700dcd839b0534d2421f179d62f53c628b216573d6ddaaf8465ded5a2d78bb89a4a3c0c27b71163de0707ece3336516fb1ced", "mail1@mail.com", nil, nil, nil, "lgTeMaPEZQ")

	mock.ExpectQuery("SELECT(.*)").WithArgs("John Doe", "mock@mail.com").WillReturnRows(rows)

	r := mux.NewRouter()
	r.HandleFunc("/users", controller.CreateUser(gormDB))

	var jsonStr = []byte(`{"username": "John Doe", "Password": "contrasena", "email": "mock@mail.com" }`)
	req, _ := http.NewRequest("POST", "/users", bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	checkResponseCode(t, http.StatusPreconditionFailed, w.Code)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func Test_CreateUser_ErrorUsernameRequest(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	gormDB, _ := gorm.Open(postgres.New(postgres.Config{
		Conn: db,
	}), &gorm.Config{})

	r := mux.NewRouter()
	r.HandleFunc("/users", controller.CreateUser(gormDB))

	var jsonStr = []byte(`{"Password": "contrasena", "email": "mock@mail.com" }`)
	req, _ := http.NewRequest("POST", "/users", bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	checkResponseCode(t, http.StatusBadRequest, w.Code)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func Test_CreateUser_Successful(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	gormDB, _ := gorm.Open(postgres.New(postgres.Config{
		Conn: db,
	}), &gorm.Config{})

	rows := sqlmock.NewRows([]string{"id", "username", "password", "email", "expire_at", "created_at", "token", "salt"})
	mock.ExpectQuery("SELECT(.*)").WithArgs("John Doe", "mock@mail.com").WillReturnRows(rows)

	r := mux.NewRouter()
	r.HandleFunc("/users", controller.CreateUser(gormDB))

	var jsonStr = []byte(`{"username": "John Doe", "Password": "contrasena", "email": "mock@mail.com" }`)
	req, _ := http.NewRequest("POST", "/users", bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	checkResponseCode(t, http.StatusCreated, w.Code)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func Test_GetToken(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	gormDB, _ := gorm.Open(postgres.New(postgres.Config{
		Conn: db,
	}), &gorm.Config{})

	rows := sqlmock.NewRows([]string{"id", "username", "password", "email", "expire_at", "created_at", "token", "salt"}).
		AddRow(1, "John Doe", "61c8c58ac621ce63e506002d16388020f8457dc140eeacb70beec3ad19b4ef7ff19ab22e42e1ab652f5520afbc52fbf75fd5764b6de92556bdd53c1eed0a5b16", "mail1@mail.com", nil, nil, nil, "lgTeMaPEZQ")

	mock.ExpectQuery("SELECT(.*)").WithArgs("John Doe").WillReturnRows(rows)

	r := mux.NewRouter()
	r.HandleFunc("/users/auth", controller.GetToken(gormDB))

	var jsonStr = []byte(`{"username": "John Doe", "Password": "contrasena"}`)
	req, _ := http.NewRequest("POST", "/users/auth", bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	checkResponseCode(t, http.StatusOK, w.Code)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func Test_GetToken_ErrorUsernameRequest(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	gormDB, _ := gorm.Open(postgres.New(postgres.Config{
		Conn: db,
	}), &gorm.Config{})

	r := mux.NewRouter()
	r.HandleFunc("/users/auth", controller.GetToken(gormDB))

	var jsonStr = []byte(`{"Password": "contrasena"}`)
	req, _ := http.NewRequest("POST", "/users/auth", bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	checkResponseCode(t, http.StatusBadRequest, w.Code)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func Test_GetToken_InvalidPassword(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	gormDB, _ := gorm.Open(postgres.New(postgres.Config{
		Conn: db,
	}), &gorm.Config{})

	var password string = "contrasena"
	var salt string = "lgTeMaPEZQ"

	rows := sqlmock.NewRows([]string{"id", "username", "password", "email", "expire_at", "created_at", "token", "salt"}).
		AddRow(1, "John Doe", hashPassword(password, salt), "mail1@mail.com", nil, nil, nil, salt)

	mock.ExpectQuery("SELECT(.*)").WithArgs("John Doe").WillReturnRows(rows)

	r := mux.NewRouter()
	r.HandleFunc("/users/auth", controller.GetToken(gormDB))

	var jsonStr = []byte(`{"username": "John Doe", "Password": "contrasenaErronea"}`)
	req, _ := http.NewRequest("POST", "/users/auth", bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	checkResponseCode(t, http.StatusNotFound, w.Code)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func Test_GetToken_UserNotExist(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	gormDB, _ := gorm.Open(postgres.New(postgres.Config{
		Conn: db,
	}), &gorm.Config{})

	rows := sqlmock.NewRows([]string{"id", "username", "password", "email", "expire_at", "created_at", "token", "salt"})

	mock.ExpectQuery("SELECT(.*)").WithArgs("John Doe").WillReturnRows(rows)

	r := mux.NewRouter()
	r.HandleFunc("/users/auth", controller.GetToken(gormDB))

	var jsonStr = []byte(`{"username": "John Doe", "Password": "contrasenaErronea"}`)
	req, _ := http.NewRequest("POST", "/users/auth", bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	checkResponseCode(t, http.StatusNotFound, w.Code)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func Test_ValidateToken_Unauthorized(t *testing.T) {

	r := mux.NewRouter()
	r.HandleFunc("/users/me", controller.VerifyToken)

	req, _ := http.NewRequest("GET", "/users/me", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImNhc29sYW5vM0BtYWlsLmNvbSIsImV4cCI6MTY3NTkxMzgyNCwiaWQiOjYsInVzZXJuYW1lIjoiQ2Fzb2xhbm8zIn0.Zimw4frWA8mIMPt7WBKMW2WKHXr8WKkIKmtItOJTudw")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	checkResponseCode(t, http.StatusUnauthorized, w.Code)

}

func Test_ValidateToken_Ok(t *testing.T) {

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	gormDB, _ := gorm.Open(postgres.New(postgres.Config{
		Conn: db,
	}), &gorm.Config{})

	var password string = "contrasena"
	var salt string = "lgTeMaPEZQ"

	rows := sqlmock.NewRows([]string{"id", "username", "password", "email", "expire_at", "created_at", "token", "salt"}).
		AddRow(1, "John Doe", hashPassword(password, salt), "mail1@mail.com", nil, nil, nil, salt)

	mock.ExpectQuery("SELECT(.*)").WithArgs("John Doe").WillReturnRows(rows)

	r := mux.NewRouter()
	r.HandleFunc("/users/auth", controller.GetToken(gormDB))

	var jsonStr = []byte(`{"username": "John Doe", "Password": "contrasena"}`)
	req, _ := http.NewRequest("POST", "/users/auth", bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	var tokenRs model.GetTokenRs
	json.NewDecoder(w.Body).Decode(&tokenRs)

	r.HandleFunc("/users/me", controller.VerifyToken)

	req2, _ := http.NewRequest("GET", "/users/me", nil)
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Authorization", "Bearer "+tokenRs.Token)
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)

	checkResponseCode(t, http.StatusOK, w2.Code)

}

func Test_ValidateToken_InvalidToken(t *testing.T) {

	r := mux.NewRouter()

	r.HandleFunc("/users/me", controller.VerifyToken)

	req, _ := http.NewRequest("GET", "/users/me", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImNhc29sYW5vM0BtYWlsLmNvbSIsImV4cCI6MTY3NjE2NTYwNiwiaWQiOjIsInVzZXJuYW1lIjoiQ2Fzb2xhbm8ifQ.A7KMwbZZ9916K-jjOzh8rDDI-t1lSCl5n0hyT26q8uo")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	checkResponseCode(t, http.StatusUnauthorized, w.Code)

}

func Test_ValidateToken_EmptyYoken(t *testing.T) {

	r := mux.NewRouter()

	r.HandleFunc("/users/me", controller.VerifyToken)

	req, _ := http.NewRequest("GET", "/users/me", nil)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	checkResponseCode(t, http.StatusBadRequest, w.Code)

}

func Test_Ping(t *testing.T) {

	r := mux.NewRouter()
	r.HandleFunc("/users/ping", controller.Ping)

	req, _ := http.NewRequest("GET", "/users/ping", nil)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	checkResponseCode(t, http.StatusOK, w.Code)

}

func checkResponseCode(t *testing.T, expected, actual int) {
	if expected != actual {
		t.Errorf("Expected response code %d. Got %d\n", expected, actual)
	}
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
