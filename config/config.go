package config

import (
	"fmt"
	"os"
	"users/model"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func Connect() (*gorm.DB, error) {
	localhost := os.Getenv("DB_HOST")
	if len(localhost) == 0 {
		localhost = "localhost"
	}
	user := os.Getenv("DB_USER")
	if len(user) == 0 {
		user = "postgres"
	}
	password := os.Getenv("DB_PASSWORD")
	if len(password) == 0 {
		password = "postgres"
	}
	port := os.Getenv("DB_PORT")
	if len(port) == 0 {
		port = "5432"
	}
	dbname := os.Getenv("DB_NAME")
	if len(dbname) == 0 {
		dbname = "monitor_users"
	}

	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable TimeZone=America/Bogota", localhost, user, password, dbname, port)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})

	if err != nil {
		panic(err.Error())
	}

	if (!db.Migrator().HasTable(&model.User{})) {
		db.Migrator().CreateTable(&model.User{})
	}

	return db, nil
}
