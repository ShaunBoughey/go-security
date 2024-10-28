// @Title Go Security API
// @Version 0.1.0
// @Description An API to check website security.
// @Host localhost:8080

package main

import (
	"log"
	"net/http"

	handler "go-security/api/handler"

	"github.com/gorilla/mux"
)

func main() {
	println("Starting API server...")
	router := mux.NewRouter().StrictSlash(true)
	registerV1Routes(router)
	println("Started successfully")
	log.Fatal(http.ListenAndServe(":8080", router))
}

func registerV1Routes(r *mux.Router) {
	sh := http.StripPrefix("/swagger/", http.FileServer(http.Dir("./swagger/")))
	r.PathPrefix("/swagger/").Handler(sh)
	// need to make dyanmic routing a thing cos this sucks
	r.HandleFunc("/security", handler.GetSecurityHeaders).Methods("GET")
	r.HandleFunc("/ssl", handler.GetSSLConfig).Methods("GET")
}
