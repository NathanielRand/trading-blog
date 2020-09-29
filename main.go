package main

import (
	"fmt"
	"net/http"

	"priva-web/controllers"
	"priva-web/views"

	"github.com/gorilla/mux"
)

var h http.Handler = http.HandlerFunc(notFound404)

var (
	homeView *views.View
	contactView *views.View
)


func notFound404(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, "<h1>404 Not Foundish</h1>")
}

func home(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	must(homeView.Render(w, nil))
}

func contact(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	must(contactView.Render(w, nil))
}

func faq(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, "<h1>FAQ</h1>")
}

// A helper function that panics on any error
func must(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	homeView = views.NewView("materialize", "views/home.html")
	contactView = views.NewView("materialize", "views/contact.html")
	usersC := controllers.NewUsers()

	r := mux.NewRouter()

	// Handle 404s
	r.NotFoundHandler = h
	
	// Assest Routes
	assetHandler := http.FileServer(http.Dir("./assets/"))
	assetHandler = http.StripPrefix("/assets/", assetHandler)
	r.PathPrefix("/assets/").Handler(assetHandler)
	
	// Image routes
	imageHandler := http.FileServer(http.Dir("./images/"))
	r.PathPrefix("/images/").Handler(http.StripPrefix("/images/", imageHandler))
	
	// User Routes 	
	r.HandleFunc("/signup", usersC.New)

	// Static routes
	r.HandleFunc("/", home)
	r.HandleFunc("/contact", contact)
	r.HandleFunc("/faq", faq)
	http.ListenAndServe(":80", r)
}
