package id1

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math"
	"net/http"
	"os"
	"regexp"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

// stateEntry records when a CSRF state token was created and the PKCE verifier.
type stateEntry struct {
	created  time.Time
	verifier string
}

// orcidIDPattern validates ORCID iD format: XXXX-XXXX-XXXX-XXX[X|digit]
var orcidIDPattern = regexp.MustCompile(`^\d{4}-\d{4}-\d{4}-\d{3}[\dX]$`)

// OrcidHandler handles the ORCID plain-OAuth2 authorization flow.
// ORCID is plain OAuth2, not OIDC.
//
// The stateStore accumulates short-lived CSRF tokens. HandleBegin prunes
// entries older than stateTTL before inserting a new one. HandleCallback
// rejects states beyond stateTTL even if they remain in the map.
type OrcidHandler struct {
	oauth2Config *oauth2.Config
	frontendURL  string
	kvStore      KeyValueStore
	stateMu      sync.Mutex
	// stateStore holds short-lived CSRF state tokens keyed by opaque string.
	// Entries must be pruned after TTL (5 minutes) to prevent unbounded growth.
	stateStore map[string]stateEntry
	stateTTL   time.Duration // must be set to 5 * time.Minute
}

// NewOrcidHandler builds an OrcidHandler from environment variables.
// Required env vars: ORCID_CLIENT_ID, ORCID_CLIENT_SECRET, ORCID_ISSUER_URL.
// Optional env vars:
//   - ORCID_REDIRECT_URL: absolute callback URL registered with ORCID
//     (e.g. http://<node_ip>:8001/auth/orcid/callback)
//   - FRONTEND_URL: URL to redirect to after successful ORCID authentication
//
// All three required vars are also checked by the caller in main.go_ before
// this function is invoked, but they are validated here too for safety.
func NewOrcidHandler(kvStore KeyValueStore) (*OrcidHandler, error) {
	issuerURL := os.Getenv("ORCID_ISSUER_URL")
	if issuerURL == "" {
		return nil, fmt.Errorf("ORCID_ISSUER_URL is required")
	}
	clientID := os.Getenv("ORCID_CLIENT_ID")
	if clientID == "" {
		return nil, fmt.Errorf("ORCID_CLIENT_ID is required")
	}
	clientSecret := os.Getenv("ORCID_CLIENT_SECRET")
	if clientSecret == "" {
		return nil, fmt.Errorf("ORCID_CLIENT_SECRET is required")
	}

	redirectURL := os.Getenv("ORCID_REDIRECT_URL")
	frontendURL := os.Getenv("FRONTEND_URL")

	return &OrcidHandler{
		oauth2Config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  issuerURL + "/oauth/authorize",
				TokenURL: issuerURL + "/oauth/token",
			},
			RedirectURL: redirectURL,
			Scopes:      []string{"/authenticate"},
		},
		frontendURL: frontendURL,
		kvStore:     kvStore,
		stateStore:  make(map[string]stateEntry),
		stateTTL:    5 * time.Minute,
	}, nil
}

// generateState returns a cryptographically secure random state token
// encoded as URL-safe base64.
func generateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate CSRF state: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// pruneExpiredStates removes state entries older than h.stateTTL.
// Caller must hold h.stateMu.
func (h *OrcidHandler) pruneExpiredStates() {
	now := time.Now()
	for k, v := range h.stateStore {
		if now.Sub(v.created) > h.stateTTL {
			delete(h.stateStore, k)
		}
	}
}

// HandleBegin starts the ORCID OAuth2 authorization flow. It generates a CSRF
// state token, PKCE verifier, prunes expired states, stores the new state and verifier,
// and redirects the browser to ORCID for authorization.
func (h *OrcidHandler) HandleBegin(w http.ResponseWriter, r *http.Request) {
	state, err := generateState()
	if err != nil {
		http.Error(w, "internal error generating auth state", http.StatusInternalServerError)
		return
	}

	verifier := oauth2.GenerateVerifier()

	h.stateMu.Lock()
	h.pruneExpiredStates()
	h.stateStore[state] = stateEntry{created: time.Now(), verifier: verifier}
	h.stateMu.Unlock()

	http.Redirect(w, r, h.oauth2Config.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier)), http.StatusFound)
}

// HandleCallback validates the CSRF state (including TTL), deletes it from the
// store, exchanges the authorization code for a token using PKCE verifier,
// extracts the ORCID iD from the token response via token.Extra("orcid"),
// validates it matches the ORCID format, and redirects to the configured
// frontend URL. If no frontend URL is configured, it returns the ORCID iD
// as a plain JSON body.
func (h *OrcidHandler) HandleCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	if state == "" {
		http.Error(w, "missing state parameter", http.StatusBadRequest)
		return
	}

	h.stateMu.Lock()
	entry, ok := h.stateStore[state]
	if ok {
		delete(h.stateStore, state)
	}
	h.stateMu.Unlock()

	if !ok {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}

	if time.Since(entry.created) > h.stateTTL {
		http.Error(w, "state expired", http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing code parameter", http.StatusBadRequest)
		return
	}

	// Exchange with exponential backoff retry (3 attempts, max 3 seconds)
	var token *oauth2.Token
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		token, err = h.oauth2Config.Exchange(r.Context(), code, oauth2.VerifierOption(entry.verifier))
		if err == nil {
			break
		}

		// Retry on any error
		if attempt < 2 {
			// Exponential backoff: 1s, 2s (doubling each time)
			backoffMs := time.Duration(math.Pow(2, float64(attempt))*1000) * time.Millisecond
			time.Sleep(backoffMs)
		}
	}

	if err != nil {
		http.Error(w, "token exchange failed", http.StatusInternalServerError)
		return
	}

	orcidID, _ := token.Extra("orcid").(string)

	if orcidID == "" {
		http.Error(w, "ORCID iD missing from token response", http.StatusBadGateway)
		return
	}

	// Validate ORCID iD format: XXXX-XXXX-XXXX-XXX[X|digit]
	if !orcidIDPattern.MatchString(orcidID) {
		http.Error(w, "invalid ORCID iD format", http.StatusBadRequest)
		return
	}

	// Get or create signing key for RS256 JWT
	keyID, privKey, err := GetOrCreateSigningKey(h.kvStore)
	if err != nil {
		http.Error(w, "Failed to get signing key", http.StatusInternalServerError)
		return
	}

	// Sign JWT with ORCID iD as subject
	jwtToken, err := signJWT(orcidID, privKey, keyID)
	if err != nil {
		http.Error(w, "Failed to sign JWT", http.StatusInternalServerError)
		return
	}

	// Return JWT instead of ORCID iD
	if h.frontendURL == "" {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"token":%q}`, jwtToken)
		return
	}

	redirectURL := h.frontendURL + "?token=" + jwtToken
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// __END_OF_FILE_MARKER__
