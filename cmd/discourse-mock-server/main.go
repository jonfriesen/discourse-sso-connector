package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"

	"github.com/gorilla/mux"
)

var (
	secret string = "some-secret"
	idpURL string = "http://localhost:8081/sso/discourse"
)

func main() {
	r := mux.NewRouter()

	r.HandleFunc("/signin", func(w http.ResponseWriter, r *http.Request) {

		// generate nonce & signature
		nonce, sig := getSSOPayload()

		// build redirect URL
		d, err := url.Parse(idpURL)
		if err != nil {
			http.Error(w, "Failed to parse idpURL", http.StatusInternalServerError)
			return
		}
		q := d.Query()
		q.Set("sso", nonce)
		q.Set("sig", sig)
		d.RawQuery = q.Encode()

		// redirect
		http.Redirect(w, r, d.String(), http.StatusMovedPermanently)

	})

	r.HandleFunc("/session/sso_login", func(w http.ResponseWriter, r *http.Request) {

		inc := r.URL.Query().Get("sso")
		incSig := r.URL.Query().Get("sig")

		b64Inc, err := url.QueryUnescape(inc)
		if err != nil {
			http.Error(w, "failed to query unescape payload", http.StatusInternalServerError)
			return
		}

		if validMAC([]byte(b64Inc), []byte(incSig), []byte(secret)) {
			fmt.Fprintln(w, "payload signature is valid")
			return
		}

		qn, err := base64.StdEncoding.DecodeString(b64Inc)
		if err != nil {
			http.Error(w, "failed to b64 decode payload", http.StatusInternalServerError)
			return
		}

		fmt.Fprintln(w, string(qn))

	})

	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello, world!")
	})

	fmt.Println("Starting mock discourse server on :8082")
	http.ListenAndServe(":8082", r)
}

func randomString(n int) string {
	var letter = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

	b := make([]rune, n)
	for i := range b {
		b[i] = letter[rand.Intn(len(letter))]
	}
	return string(b)
}

func validMAC(message, messageMAC, key []byte) bool {
	expectedMac := createMac(message, key)
	return hmac.Equal(messageMAC, expectedMac)
}

func createMac(message, secret []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write(message)
	sha := mac.Sum(nil)
	return sha
}

func getSSOPayload() (string, string) {

	// generate random nonce
	nonce := "nonce=" + randomString(32)

	// base64 nonce
	b64nonce := base64.StdEncoding.EncodeToString([]byte(nonce))

	// generate HMAC-256 signature
	sig := createMac([]byte(b64nonce), []byte(secret))

	return b64nonce, hex.EncodeToString(sig)

}
