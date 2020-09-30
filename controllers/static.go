package controllers

import (
	"priva-web/views"
)

type Static struct {
	Home    *views.View
	Contact *views.View
}

func NewStatic() *Static {
	return &Static{
		Home: views.NewView(
			"materialize", "static/home"),
		Contact: views.NewView(
			"materialize", "static/contact"),
	}
}
