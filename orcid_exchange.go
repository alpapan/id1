// apps/id1/orcid_exchange.go
//
// group: auth
// tags: orcid, oauth, authentication, single-use
// summary: One-time login code that carries the ORCID-issued JWT to the browser,
// and the endpoint that redeems it. The JWT never appears in a URL.
//
//

package id1

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"
)

const (
	// orcidCodePrefix is the id1 KV namespace for in-flight ORCID login codes. Its
	// Id segment equals orcidCodePrefix so the TTL-scheduled delete self-authorizes
	// in dotAfter (auth(orcidCodePrefix, del) -> Key.Id == orcidCodePrefix),
	// as _authstate and _syncticket do. The leading underscore cannot collide
	// with an ORCID iD.
	orcidCodePrefix = "_orcidcode"
	// orcidCodeTTL bounds a code's lifetime in seconds. The browser redeems it
	// within a page load of receiving it, so a short window is ample, and the code
	// is single-use besides.
	orcidCodeTTL = "60"
	// orcidCodeLifetime is orcidCodeTTL as a duration. The exchange enforces it
	// itself, so a code is refused at once on expiry rather than at the sweeper's
	// next pass.
	orcidCodeLifetime = 60 * time.Second
	// orcidExchangeBodyLimit caps the request body HandleExchange reads. A code is
	// 43 characters, so this is generous.
	orcidExchangeBodyLimit = 1024
)

// orcidCodeNow is the clock the code lifetime is measured against. It is a
// variable so a test can move time past the lifetime.
var orcidCodeNow = time.Now

// orcidCodePattern matches exactly what storeOrcidLoginCode issues: 32 random
// bytes in unpadded URL-safe base64, which is 43 characters.
var orcidCodePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// orcidCodeEntry is the stored value of a login code: the JWT and the instant
// the code stops being redeemable.
type orcidCodeEntry struct {
	JWT     string `json:"jwt"`
	Expires int64  `json:"exp"`
	Bind    string `json:"bind"`
}

// storeOrcidLoginCode stores jwtToken in the id1 KV store under a fresh
// one-time code and returns the code. 32 random bytes -> unpadded base64url
// (alphabet A-Za-z0-9-_), so the code is a single, path-safe KV key segment.
// The same shape as the sync ticket in sync_ticket.go.
func storeOrcidLoginCode(jwtToken, bind string) (string, error) {
	codeBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, codeBytes); err != nil {
		return "", fmt.Errorf("failed to generate login code: %w", err)
	}
	code := base64.RawURLEncoding.EncodeToString(codeBytes)

	codeKey, err := KK(orcidCodePrefix, code)
	if err != nil {
		return "", fmt.Errorf("failed to build login code key: %w", err)
	}
	entry, err := json.Marshal(orcidCodeEntry{
		JWT:     jwtToken,
		Expires: orcidCodeNow().Add(orcidCodeLifetime).Unix(),
		Bind:    bind,
	})
	if err != nil {
		return "", fmt.Errorf("failed to encode login code: %w", err)
	}
	if _, err := CmdSet(codeKey,
		map[string]string{"x-id": orcidCodePrefix, "ttl": orcidCodeTTL},
		entry).execUnauthorised(); err != nil {
		return "", fmt.Errorf("failed to store login code: %w", err)
	}
	return code, nil
}

// HandleExchange redeems a one-time login code for the id1 JWT that
// HandleCallback minted.
//
// Auth contract: no bearer credential, but a browser binding. The code is
// redeemable only by the browser that began the login: the request must carry
// the binding cookie HandleBegin set, whose digest the code entry stores. The
// code is 256 bits of randomness, is burned by a
// delete-first CmdDel on its leaf key (a single-winner atomic unlink), and is
// scheduled to expire 60 seconds after issue. The stored entry carries its own
// expiry instant, which this handler checks on redemption; the TTL sweeper only
// reclaims the key afterwards. A second redemption, an unknown code, an expired
// code, a swept code and a code presented without its binding all answer 401
// "Invalid or expired code"; a refused binding still burns the code. A malformed request
// answers 400. The
// response is never cached. No CORS headers are set: the browser calls this
// same-origin through Traefik.
func (h *OrcidHandler) HandleExchange(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var body struct {
		Code string `json:"code"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, orcidExchangeBodyLimit)
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	// Reject an empty code BEFORE the KV delete: KK(orcidCodePrefix, "")
	// normalises to the bare _orcidcode directory, whose delete would remove
	// every live code.
	if body.Code == "" {
		http.Error(w, "Missing code", http.StatusBadRequest)
		return
	}
	// SECURITY: the code is attacker-controlled and becomes a KV key segment.
	// Only the exact alphabet and length storeOrcidLoginCode issues gets through,
	// which excludes "/" and "." so a crafted code cannot path-traverse.
	if !orcidCodePattern.MatchString(body.Code) {
		http.Error(w, "Invalid or expired code", http.StatusUnauthorized)
		return
	}
	codeKey, keyErr := KK(orcidCodePrefix, body.Code)
	if keyErr != nil {
		http.Error(w, "Invalid or expired code", http.StatusUnauthorized)
		return
	}

	// Recover the JWT BEFORE burning the code. This CmdGet decides nothing: the
	// CmdDel below is the sole gate, because a presence check followed by a
	// delete would let two requests both pass. The read happens first only so
	// the value is available after this call has won the delete.
	jwtBytes, _ := CmdGet(codeKey).execUnauthorised()

	// Burn by delete-first: the code is a leaf key, so the delete is a
	// single-winner atomic unlink. Only the call that wins it (err == nil) may
	// return the JWT; the loser of a race, an unknown code and an expired
	// (TTL-swept) code all get a non-nil error.
	if _, err := CmdDel(codeKey).execUnauthorised(); err != nil {
		http.Error(w, "Invalid or expired code", http.StatusUnauthorized)
		return
	}
	var entry orcidCodeEntry
	if err := json.Unmarshal(jwtBytes, &entry); err != nil || entry.JWT == "" {
		http.Error(w, "Invalid or expired code", http.StatusUnauthorized)
		return
	}
	if !orcidCodeNow().Before(time.Unix(entry.Expires, 0)) {
		http.Error(w, "Invalid or expired code", http.StatusUnauthorized)
		return
	}

	// SECURITY: only the browser the login began in may redeem the code. The
	// code is already burned, so a leaked code presented without the binding
	// is useless to everyone.
	if !requestBindingMatches(r, entry.Bind) {
		http.Error(w, "Invalid or expired code", http.StatusUnauthorized)
		return
	}

	http.SetCookie(w, h.bindCookie("", -1))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"jwt": entry.JWT})
}

// __END_OF_FILE_MARKER__
