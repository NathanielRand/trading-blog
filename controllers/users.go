package controllers

import (
	"net/http"

	"priva-web/views"
)

func NewUsers() *Users {
	return &Users{
		NewView: views.NewView("materialize", "views/users/new.html"),
	}
}

type Users struct {
	NewView *views.View
}

// New is used to render the form where a user can
// create a new user account.
//
// GET /signup
func (u *Users) New(w http.ResponseWriter, r *http.Request) {
	if err := u.NewView.Render(w, nil); err != nil {
		panic(err)
	}
}
