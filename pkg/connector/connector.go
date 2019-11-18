package connector

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/go-querystring/query"
	"github.com/gorilla/sessions"
	"github.com/pkg/errors"
)

// Connector is a configured SSO connector using the Discourse protocol
type Connector struct {
	secret       string
	discourseURL string
	cookieKey    []byte
	cookieName   string
	authHandler  AuthHandler
	errorHandler ErrorHandler
}

var (
	ErrSignatureMistmatch      = errors.New("Signature does not match message")
	ErrMissingDiscoursePayload = errors.New("Missing Discourse payload or signature")
)

// Response holds the values that will be sent back to Discourse that identify a user
// nonce, external_id, and email are required
type Response struct {
	Nonce              string `url:"nonce"`
	ExternalID         string `url:"external_id"`
	Email              string `url:"email"`
	Name               string `url:"name,omitempty"`
	Username           string `url:"username,omitempty"`
	RequireActivation  bool   `url:"require_activation,omitempty"`
	AvatarURL          string `url:"avatar_url,omitempty"`
	AvatarForceUpdate  bool   `url:"avatar_force_update,omitempty"`
	Bio                bool   `url:"bio,omitempty"`
	IsAdmin            bool   `url:"admin,omitempty"`
	IsModerator        bool   `url:"moderator,omitempty"`
	SuppressWelcomeMsg bool   `url:"suppress_welcome_message,omitempty"`
}

// Option is a function signature that can be used to configure the Connector
type Option func(*Connector)

// ErrorHandler is a function that is called when an error occurs, this can be customized
type ErrorHandler func(http.ResponseWriter, *http.Request, int, string)

// AuthHandler is a function that authenticates a user from a request and returns a connector.Response
type AuthHandler func(http.ResponseWriter, *http.Request) (*Response, error)

// WithCookieKey is an optional configuration for setting a secure cookie
func WithCookieKey(key string) Option {
	return func(c *Connector) {
		c.cookieKey = []byte(key)
	}
}

// WithCookieName is an optional configuration for setting a cookie name
func WithCookieName(name string) Option {
	return func(c *Connector) {
		c.cookieName = name
	}
}

// WithErrorHandler is called when an error occurs
func WithErrorHandler(handler ErrorHandler) Option {
	return func(c *Connector) {
		c.errorHandler = handler
	}
}

// NewConnector creates a connector object
func NewConnector(secret, discourseURL string, authHandler AuthHandler, opts ...Option) *Connector {
	// create connector with defaults / required args
	c := &Connector{
		secret:       secret,
		discourseURL: discourseURL,
		cookieKey:    []byte("discourse-connector"),
		cookieName:   "discourse-connector",
		authHandler:  authHandler,
		errorHandler: func(w http.ResponseWriter, r *http.Request, status int, message string) {
			http.Error(w, message, status)
		},
	}

	// apply configs
	for _, opt := range opts {
		opt(c)
	}

	return c
}

// GetValidationMiddleware will validate the nonce & signature then stores it in a cookie
// before continueing to the apps login page. This cookie has a 10 minute expiry and is
// used to get the nonce and signature to the authentication validation step. It is not
// explicitly needed as long as the payload and signature get to the final payload step.
func (c *Connector) GetValidationMiddleware(f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// validate sso and sig are present in URL query params
		inc := r.URL.Query().Get("sso")
		incSig := r.URL.Query().Get("sig")

		// if params are missing eject
		if inc == "" || incSig == "" {
			c.errorHandler(w, r, http.StatusBadRequest, ErrMissingDiscoursePayload.Error())
			return
		}

		// validate payload signature
		if err := c.ValidateDiscourseSignature(inc, incSig); err != nil {
			c.errorHandler(w, r, http.StatusInternalServerError, err.Error())
			return
		}

		// set cookie with payload, sig, and 10 minute expiry
		store := sessions.NewCookieStore(c.cookieKey)
		session, _ := store.Get(r, c.cookieName)
		session.Options = &sessions.Options{
			Path:     "/",
			MaxAge:   10 * 60, // ten minutes (Discourse nonce expires after this point)
			HttpOnly: true,
		}
		session.Values["sso"] = inc
		session.Values["sig"] = incSig
		session.Save(r, w)

		// go to next func in middleware
		f(w, r)
	}
}

// GetHandler returns an HTTP Handler for SSO Auth against Discourse
func (c *Connector) GetHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		store := sessions.NewCookieStore(c.cookieKey)
		session, _ := store.Get(r, c.cookieName)

		// get payload and sig from cookie and validate
		inc := session.Values["sso"].(string)
		incSig := session.Values["sig"].(string)

		// if params are missing eject
		if inc == "" || incSig == "" {
			c.errorHandler(w, r, http.StatusBadRequest, ErrMissingDiscoursePayload.Error())
			return
		}

		// validate payload signature
		if err := c.ValidateDiscourseSignature(inc, incSig); err != nil {
			c.errorHandler(w, r, http.StatusInternalServerError, err.Error())
			return
		}

		// perform authentication strategy
		cr, err := c.authHandler(w, r)
		if err != nil {
			// FUTURE: add a custom writer to monitor if the user handles
			// writing back to the user, if not we can add a default http response
			log.Printf("AuthHandler errored: %s", err.Error())
			return
		}

		// pull actual nonce
		nonce, err := getNonce(inc)
		if err != nil {
			c.errorHandler(w, r, http.StatusInternalServerError, err.Error())
			return
		}

		// set nonce on response object
		cr.Nonce = nonce

		// check that the response is valid
		if err := cr.Valid(); err != nil {
			c.errorHandler(w, r, http.StatusInternalServerError, err.Error())
			return
		}

		// create response payload for discourse
		payload, sig, err := c.Payload(cr)
		if err != nil {
			c.errorHandler(w, r, http.StatusInternalServerError, err.Error())
			return
		}

		redirectURL, err := c.buildRedirectURL(payload, sig)
		if err != nil {
			c.errorHandler(w, r, http.StatusInternalServerError, err.Error())
			return
		}

		// redirect back to discourse
		http.Redirect(w, r, redirectURL, http.StatusMovedPermanently)

	}
}

// ValidateDiscourseSignature will check that an HMAC-256 signature matches the appropriate message
func (c *Connector) ValidateDiscourseSignature(message, signature string) error {
	s, err := hex.DecodeString(signature)
	if err != nil {
		return errors.Wrap(err, "failed to decode signature")
	}
	if !validMAC([]byte(message), s, []byte(c.secret)) {
		return ErrSignatureMistmatch
	}

	return nil
}

// Payload creates a URL query value list, base64'd, URL path encoded again, with a signature
func (c *Connector) Payload(r *Response) (string, string, error) {

	// generate signature
	sig, err := r.generateSignature(c.secret)
	if err != nil {
		return "", "", err
	}

	// get payload
	q, err := r.base64Query()
	if err != nil {
		return "", "", err
	}

	return q, sig, nil

}

// validMAC reports whether messageMAC is a valid HMAC tag for message.
func validMAC(message, messageMAC, key []byte) bool {
	expectedMac := createMac(message, key)
	return hmac.Equal(messageMAC, expectedMac)
}

// createMac creates a HMAC-256 signature for a message
func createMac(message, secret []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write(message)
	sha := mac.Sum(nil)
	return sha
}

func (r *Response) plainTextQuery() (string, error) {
	v, err := query.Values(r)
	if err != nil {
		return "", errors.New("failed creating url encoded query")
	}

	return v.Encode(), nil
}

func (r *Response) base64Query() (string, error) {
	q, err := r.plainTextQuery()
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString([]byte(q)), nil
}

func (r *Response) generateSignature(secret string) (string, error) {
	q, err := r.base64Query()
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(createMac([]byte(q), []byte(secret))), nil
}

// Valid returns if the Response meets the minimum requirements
func (r *Response) Valid() error {
	errList := []string{}

	if r.Nonce == "" {
		errList = append(errList, "missing nonce")
	}

	if r.Email == "" {
		errList = append(errList, "missing email")
	}

	if r.ExternalID == "" {
		errList = append(errList, "missing external ID")
	}

	if len(errList) == 0 {
		return nil
	}

	return fmt.Errorf("Connector Response invalid: %s", strings.Join(errList, ", "))
}

func (c *Connector) buildRedirectURL(payload, signature string) (string, error) {

	d, err := url.Parse(c.discourseURL)
	if err != nil {
		return "", err
	}

	d.Path = "/session/sso_login"
	q := d.Query()
	q.Set("sso", payload)
	q.Set("sig", signature)
	d.RawQuery = q.Encode()

	return d.String(), nil
}

func getNonce(encodedNonce string) (string, error) {
	b64, err := url.QueryUnescape(encodedNonce)
	if err != nil {
		return "", errors.New("failed to query unescape nonce payload")
	}

	qn, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", errors.New("failed to base64 decode nonce payload")
	}

	if !strings.HasPrefix(string(qn), "nonce=") {
		return "", errors.New("incorrect nonce form (eg nonce=<nonce_value>)")
	}

	return strings.TrimPrefix(string(qn), "nonce="), nil

}
