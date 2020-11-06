package views

import (
	"log"
)

const (
	AlertLvlError   = "danger"
	AlertLvlWarning = "warning"
	ALertLvlInfo    = "info"
	AlertLvlSuccess = "success"
	
	// AlertMsgGeneric is displayed when any random error
	// is encountered by our backend.
	AlertMsgGeneric = "Something went wrong. Please try again " +
		"or contact us if the problem continues."
)

// Data is the top level structure that views
// expect data to come in.
type Data struct {
	Alert *Alert
	Yield interface{}
}

// Alert is used to render Materialize Alert messages in templates.
type Alert struct {
	Level   string
	Message string
}

type PublicError interface {
	// The error type is actually an interface in Go, 
	// defining any type with an Error method that 
	// returns a string. That means we can embed 
	// that interface into our PublicError interface 
	// to ensure our public errors also work as regular errors. 	
	error
	// Anything that implements the PublicError interface
	// to have a Public method that can be used to return 
	// an error message intended to be displayed to our end users. 	
	Public() string
}

// SetAlert method allows us to easily set an 
// alert on our Data type using an error.
func (d *Data) SetAlert(err error) {
	var msg string
	if pErr, ok := err.(PublicError); ok {
		msg = pErr.Public()
	} else {
		log.Println(err)
		msg = AlertMsgGeneric
	}
	d.Alert = &Alert{
		Level: AlertLvlError,
		Message: msg,
	}
}

// AlertError func makes it easier write custom
// error messages by constructing the Alert object here.
func (d *Data) AlertError(msg string) {
	d.Alert = &Alert{
		Level: AlertLvlError,
		Message: msg,
	}
}