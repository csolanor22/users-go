package model

import "time"

type User struct {
	Id        int       `form:"id" json:"id"`
	Username  string    `form:"username" json:"username"`
	Email     string    `form:"email " json:"email"`
	Password  string    `form:"password " json:"password"`
	Salt      string    `form:"salt " json:"salt"`
	Token     string    `form:"token " json:"token"`
	ExpireAt  time.Time `form:"expireAt" json:"expireAt"`
	CreatedAt time.Time `form:"createdAt" json:"createdAt"`
}

type NewUserRequest struct {
	Username string `json:"username"  validate:"required,min=1"`
	Password string `validate:"required" json:"password"`
	Email    string `validate:"required,email" json:"email"`
}

type NewUserCreated struct {
	Id        int       `form:"id" json:"id"`
	CreatedAt time.Time `form:"createdAt" json:"createdAt"`
}

type GetTokenRq struct {
	Username string `json:"username"  validate:"required,min=1"`
	Password string `validate:"required,min=1" json:"password"`
}

type GetTokenRs struct {
	Id       int       `form:"id" json:"id"`
	Token    string    `form:"token " json:"token"`
	ExpireAt time.Time `form:"expireAt" json:"expireAt"`
}

type VerifyTokenRs struct {
	Id       int    `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
}
