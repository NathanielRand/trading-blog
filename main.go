package main

import (
	"fmt"
	"net/http"

	"priva-web/controllers"
	"priva-web/models"

	"github.com/gorilla/mux"
)

const (
	host = "localhost"
	port = 5432
	user = "postgres"
	password = "temppassword"
	dbname = "priva_dev"

)

var h http.Handler = http.HandlerFunc(notFound404)

func notFound404(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, "<h1>404 Not Foundish</h1>")
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
	// Create a DB connection string and then use it to
	// create our model service.
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s " +
		"password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)
	us, err := models.NewUserService(psqlInfo)
	if err != nil {
		panic(err)
	}
	defer us.Close()
	us.AutoMigrate()
	
	// Controllers
	staticC := controllers.NewStatic()
	usersC := controllers.NewUsers(us)

	// Router
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
	r.HandleFunc("/signup", usersC.New).Methods("GET")
	r.HandleFunc("/signup", usersC.Create).Methods("POST")
	r.Handle("/login", usersC.LoginView).Methods("GET")
	r.HandleFunc("/login", usersC.Login).Methods("POST")
	
	// Misc. Routes
	r.HandleFunc("/cookietest", usersC.CookieTest).Methods("GET")

	// Static routes
	r.Handle("/", staticC.Home).Methods("GET")
	r.Handle("/contact", staticC.Contact).Methods("GET")
	r.HandleFunc("/faq", faq).Methods("GET")
	http.ListenAndServe(":80", r)
}
