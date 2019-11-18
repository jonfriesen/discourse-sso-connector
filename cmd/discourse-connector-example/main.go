package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jonfriesen/discourse-sso-connector/pkg/connector"
)

var (
	secret       string = "some-secret"
	discourseURL string = "http://localhost:8082"
)

const (
	signinHTML = `
<!DOCTYPE html>
<html>
<body>
<h2>Discourse SSO Connector</h2>
<form action="/sso/discourse" method="post">
	<input type="submit" value="Login as Alice">
</form> 
</body>
</html>`
)

func main() {

	// This is where you will create a function that will authenticate your user
	// it will probably include pulling auth data from the handler then checking
	// your database to validate, finally creating the connector.Response object
	// which will be used by Discourse to authenticate the user
	// For failures, write a message back to the http call and throw an error
	// the connector logic will stop at that point
	authHandler := func(w http.ResponseWriter, r *http.Request) (*connector.Response, error) {
		return &connector.Response{
			Email:      "alice.smith@example.com",
			ExternalID: "100",
		}, nil
	}

	// Create a connector instance with a secret, discourseURL, and authHandler
	// - secret should be the same one entered in your discourse SSO settings
	// - discourseURL should be your top level discourse site (eg http://discuss.example.com)
	// - authHandler is similar to an http.HandlerFunc but returns a connector.Response and an error
	// 	 if any error is returned the Discourse auth process will stop. You're encouraged to handle
	// 	 this scenario as you would normally (eg. showing a message on signin orredirecting to an error page)
	c := connector.NewConnector(secret, discourseURL, authHandler)

	// This function should wrap your login page handler to verify the payload
	// signature is correct right away, if there are any issues it will all the
	// errorHandler which is customizable
	discourseValidationMiddlewareFn := c.GetValidationMiddleware

	// Get the handler that will take the Response object, do all of the encoding and validation
	// then redirect the user back to discourse where they will be authenticated
	discourseAuthHandler := c.GetHandler()

	// This will display some sort of authentication, for example a login page
	signinHandler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, signinHTML)
	}

	r := mux.NewRouter()

	// Here we create a custom endpoint for our Discourse SSO because of the middleware and endpoint.
	// This strategy reuses the signin method from the default app (which doesn't really exist) but validates
	// that it gets the correct payload and signature then stores it as a timed cookie (Discourse expires it's
	// nonce after 10 minutes)
	r.HandleFunc("/sso/discourse", discourseValidationMiddlewareFn(signinHandler)).Methods("GET")
	r.HandleFunc("/sso/discourse", discourseAuthHandler).Methods("POST")

	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello, world!")
	})

	fmt.Println("Starting example identity provider server on :8081")
	http.ListenAndServe(":8081", r)
}
