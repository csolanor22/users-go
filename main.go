package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"users/config"
	"users/controller"

	"github.com/gorilla/mux"
	_ "gorm.io/driver/postgres"
)

func main() {
	db, err_db := config.Connect()
	if err_db != nil {
		log.Panic(err_db)
		return
	}
	port := os.Getenv("CONFIG_PORT")
	if len(port) == 0 {
		port = "3000"
	}

	router := mux.NewRouter()
	router.HandleFunc("/users", controller.CreateUser(db)).Methods("POST")
	router.HandleFunc("/users/auth", controller.GetToken(db)).Methods("POST")
	router.HandleFunc("/users/me", controller.VerifyToken).Methods("GET")
	router.HandleFunc("/users/ping", controller.Ping).Methods("GET")
	http.Handle("/", router)
	fmt.Println("Connected to port " + port)
	log.Fatal(http.ListenAndServe(":"+port, router))
}
