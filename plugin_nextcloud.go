// apps/backend/containers/id1/plugin_nextcloud.go
//
// group: config
// tags: nextcloud, plugin, integration, webdav
// summary: Nextcloud integration plugin for WebDAV file synchronization.
// Proxies Nextcloud requests with HMAC-signed authentication.
//
//

package id1

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// orcidPattern matches the standard ORCID iD format: XXXX-XXXX-XXXX-XXXX
// where X is a digit (last character may also be 'X' checksum).
var orcidPattern = regexp.MustCompile(`^\d{4}-\d{4}-\d{4}-\d{3}[\dX]$`)

// ocsProvisioningHints maps known OCS Provisioning API statuscodes to
// human-readable hints. Used to annotate error messages so operators can
// diagnose failures without looking up the code in Nextcloud docs.
// Reference: https://docs.nextcloud.com/server/latest/admin_manual/configuration_user/instruction_set_for_users.html
var ocsProvisioningHints = map[int]string{
	101: "invalid input (check userid format and password policy)",
	103: "unknown error while adding user",
	104: "group does not exist",
	105: "insufficient privileges for group",
	106: "no group specified (required for subadmins)",
	107: "password policy violation (e.g. common password, too short)",
	108: "password generation failed",
	109: "failed to create user (database insert error)",
	110: "required email address is missing",
	111: "invalid email address",
	112: "invalid language",
	113: "invalid quota value",
}

// ocsAuthHints maps known OCS core/getapppassword statuscodes to hints.
var ocsAuthHints = map[int]string{
	403: "forbidden (credentials rejected or session-based auth required)",
	997: "unauthorised (basic auth failed)",
}

// ErrNextcloudCredentialsRejected reports that Nextcloud refused the derived
// login password. Two conditions produce it and neither is recoverable by
// minting alone: the account does not exist yet, or it exists with a password
// that no longer matches what the derivation key produces. The caller decides
// whether to provision and retry.
var ErrNextcloudCredentialsRejected = errors.New("nextcloud rejected the derived credentials")
var ErrNextcloudRateLimited = errors.New("nextcloud is rate-limiting requests")

// ncHTTPClientTimeout bounds a single OCS round trip. Every handler budget
// below must be strictly smaller, or the handler's own context stops being the
// binding bound and becomes decoration.
const ncHTTPClientTimeout = 30 * time.Second

// NcMintUserAgent is sent on every OCS mint request. Nextcloud names an app
// password after the User-Agent of the request that created it, so this string
// is what identifies a Curatorium-minted app password in
// `occ user:auth-tokens:list` output. Any consumer that selects tokens for
// revocation matches on it, so changing it changes which tokens are selectable.
const NcMintUserAgent = "curatorium-auth/1"

// NcTokenTimeout bounds the mint-only token handler. The warm path costs
// ~1.24s against a healthy Nextcloud in the steady state (one attempt); with
// a rotation fallback armed, the worst case is two sequential attempts under
// one shared budget, so headroom is tighter. A 5s budget is sufficient for two
// healthy round trips with margin, and must stay strictly smaller than
// ncHTTPClientTimeout (30s) so socket timeouts do not hide handler timeouts.
//
// Edge case: a brand-new user's first request is a credentials rejection by
// construction (the account does not exist yet), so with the fallback armed it
// always takes the two-attempt path. If the second attempt alone exhausts the
// remaining shared budget, the handler answers 504 instead of 409, and the
// caller's provisioning path (nextcloud_credentials.py in the backend)
// provisions only on 409 - a 504 is simply not provisioned on that request,
// and it self-corrects on the caller's next one. This is accepted rather than
// sized against len(keys) round trips because the rotation window, when the
// ~1.24s warm-path figure above is least trustworthy (Nextcloud is also mid
// password-reset pass), is transient, and a wider budget would slow the
// steady-state timeout too.
const NcTokenTimeout = 5 * time.Second

// NcProvisionTimeout bounds the account-provisioning handler. Account creation
// is slow and runs off any request path, so it gets a far wider budget than
// minting.
const NcProvisionTimeout = 25 * time.Second

// NcDerivationKeyBytes is the decoded length `openssl rand -hex 32` produces,
// which is what provisions NC_DERIVATION_KEY.
const NcDerivationKeyBytes = 32

// NcEndpointsEnabled reports whether the two /internal/nc-* endpoints have
// everything they need: a non-empty internal secret, and a derivation key that
// decodes from hex to exactly NcDerivationKeyBytes. Both derive the user's
// password from derivationKeyHex and both refuse every caller when
// internalSecret is empty, so registering them without a secret would turn every
// Nextcloud file operation into a 401 with nothing at startup to say why.
// Leaving the paths unrouted instead makes the misconfiguration a 404 plus one
// startup line, which is diagnosable.
//
// A key that does not decode, and one that decodes to the wrong length, are
// treated identically: neither can produce the passwords
// `curatorium admin nextcloud rotate-derivation-key` computes for the same
// key, so registering with either derives a wrong or weakened password for
// every user. Rejecting them here rather than aborting keeps ORCID login,
// JWKS and the sovereign-key surface serving, which a Nextcloud
// misconfiguration must not take down.
func NcEndpointsEnabled(derivationKeyHex, internalSecret string) bool {
	if derivationKeyHex == "" || internalSecret == "" {
		return false
	}
	decoded, err := hex.DecodeString(derivationKeyHex)
	return err == nil && len(decoded) == NcDerivationKeyBytes
}

// NcPreviousDerivationKey decodes the superseded derivation key a rotation
// leaves behind, reporting whether it is usable as a fallback.
//
// Unset is the steady state - a deployment that has never rotated has no
// previous key - so the empty string is answered false with no complaint. A
// value that is set but does not decode to exactly NcDerivationKeyBytes is a
// different thing entirely: an operator meant an overlap to exist and will not
// get one, and every account whose Nextcloud password still derives from the
// old key is refused until the rotation finishes. The caller distinguishes the
// two by testing the raw string for emptiness itself, and reports the second.
//
// A rejected key returns no bytes at all rather than a partial decode: half of
// a derivation key derives a password nothing accepts, so handing one back
// would arm a fallback that can only ever cost a wasted round trip.
func NcPreviousDerivationKey(previousKeyHex string) ([]byte, bool) {
	if previousKeyHex == "" {
		return nil, false
	}
	decoded, err := hex.DecodeString(previousKeyHex)
	if err != nil || len(decoded) != NcDerivationKeyBytes {
		return nil, false
	}
	return decoded, true
}

// NcPreviousKeyForFallback decides whether the previous Nextcloud derivation
// key arms the rotation fallback, and gives the one line main.go_ should
// print about that decision. main.go_ is never compiled by `go test ./...`
// (see apps/id1/CLAUDE.md's extraction pattern), so moving the decision here
// is what makes it reachable by the unit suite.
//
// previousKeyHex empty is the steady state and answers with a nil key and an
// empty logLine, so the caller prints nothing. A previousKeyHex that
// NcPreviousDerivationKey rejects (wrong length, not hex) answers with a nil
// key and a non-empty logLine: an operator meant an overlap to exist and is
// not getting one. A previousKeyHex that decodes but is byte-identical to
// currentKey gives the fallback nothing to fall back to, so it is dropped the
// same way even though it decoded cleanly - compared in constant time because
// both are secret key material. Anything else is armed.
func NcPreviousKeyForFallback(previousKeyHex string, currentKey []byte) (previousKey []byte, logLine string) {
	decoded, usable := NcPreviousDerivationKey(previousKeyHex)
	if !usable {
		if previousKeyHex == "" {
			return nil, ""
		}
		return nil, "NC_DERIVATION_KEY_PREV is set but unusable (it must be 32 hex-encoded bytes, as produced by `openssl rand -hex 32`); the rotation fallback is NOT armed, so every account whose Nextcloud password still derives from the previous key is refused until its reset runs"
	}
	if subtle.ConstantTimeCompare(decoded, currentKey) == 1 {
		return nil, "NC_DERIVATION_KEY_PREV is set and usable but equals NC_DERIVATION_KEY; the rotation fallback is NOT armed because both slots hold the same value, so every account whose Nextcloud password still derives from the previous key is refused until its reset runs"
	}
	return decoded, "NC_DERIVATION_KEY_PREV is set and usable; /internal/nc-token accepts the previous key as a fallback while a rotation completes"
}

// formatOCSError returns a diagnostic error wrapping (code, message, hint).
// hints is the applicable code->hint map (provisioning vs auth).
func formatOCSError(endpoint string, code int, message string, hints map[int]string) error {
	if hint, ok := hints[code]; ok {
		return fmt.Errorf("OCS error %d at %s: %s (%s)", code, endpoint, message, hint)
	}
	return fmt.Errorf("OCS error %d at %s: %s", code, endpoint, message)
}

// OCSResponse represents the OCS API response format used by Nextcloud.
type OCSResponse struct {
	OCS OCSData `json:"ocs"`
}

// OCSData contains the OCS response metadata and data.
type OCSData struct {
	Meta OCSMeta     `json:"meta"`
	Data interface{} `json:"data"`
}

// OCSMeta contains the OCS response status information.
type OCSMeta struct {
	Statuscode int    `json:"statuscode"`
	Status     string `json:"status"`
	Message    string `json:"message"`
}

// ncRejectionStreakAlertThreshold is how many mint rejections one user must
// collect, with no successful mint of their own between them, before the run is
// reported. An account that does not exist yet is refused with HTTP 401, so a
// lone rejection is ordinary first-login traffic; a user refused over and over
// is not, whether because NEXTCLOUD_URL is misaimed or because their password
// has diverged from the derivation key. Provisioning cannot repair the latter,
// so nothing else would ever report it.
const ncRejectionStreakAlertThreshold = 5

// ncRejectionStreakMaxTracked bounds the streak table. Entries are removed on a
// successful mint, so it holds only users currently being refused - normally
// none. The cap covers the pathological case where Nextcloud refuses everyone:
// the table is diagnostic state only, so past the cap it is simply dropped,
// which costs at worst a delayed alert.
const ncRejectionStreakMaxTracked = 10000

// NextcloudClient is a minimal HTTP client for Nextcloud's OCS API. It is safe
// to share across goroutines: its configuration is fixed once constructed, and
// the one piece of mutable state - the per-user rejection streaks behind
// MintAppToken's misconfiguration alert - is mutex-guarded.
type NextcloudClient struct {
	URL      string
	Username string
	Password string

	// rejectionStreaks counts consecutive refused mints per ORCID, cleared for
	// that ORCID as soon as one of their mints succeeds. It exists only to tell
	// an expected first-login refusal apart from a user who is never going to
	// authenticate; nothing reads it for control flow.
	rejectionStreaksMu sync.Mutex
	rejectionStreaks   map[string]int
}

// NewNextcloudClient reads configuration from environment variables
// (NEXTCLOUD_URL, NC_PROVISIONER_USER, NC_PROVISIONER_PASSWORD). Returns a
// client with empty fields if variables are unset; callers that require all
// fields must check for zero values.
func NewNextcloudClient() *NextcloudClient {
	return &NextcloudClient{
		URL:      os.Getenv("NEXTCLOUD_URL"),
		Username: os.Getenv("NC_PROVISIONER_USER"),
		Password: os.Getenv("NC_PROVISIONER_PASSWORD"),
	}
}

// EnsureUserExists ensures a Nextcloud user with the given ORCID and derived
// password exists. Accepts OCS statuscodes 100 (v1 "created"), 200 (v2 "OK"),
// and 102 ("already exists") as success. Returns error for any other status.
func (c *NextcloudClient) EnsureUserExists(ctx context.Context, orcid, password string) error {
	endpoint := c.URL + "/ocs/v2.php/cloud/users?format=json"
	formData := url.Values{
		"userid":   {orcid},
		"password": {password},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(formData.Encode()))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("OCS-APIREQUEST", "true")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.Username, c.Password)

	client := &http.Client{Timeout: ncHTTPClientTimeout}
	if transport, _ := BuildTLSTransport(); transport != nil {
		client.Transport = transport
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	var ocsResult OCSResponse
	if err := json.NewDecoder(resp.Body).Decode(&ocsResult); err != nil {
		return fmt.Errorf("decode OCS response: %w", err)
	}
	switch ocsResult.OCS.Meta.Statuscode {
	case 100, 102, 200:
		return nil
	default:
		return formatOCSError("/cloud/users", ocsResult.OCS.Meta.Statuscode, ocsResult.OCS.Meta.Message, ocsProvisioningHints)
	}
}

// MintAppToken calls Nextcloud's getapppassword endpoint as the given user
// (BasicAuth with the user's derived login password) and returns the plaintext
// app token. OCS statuscode 200 is the only success.
//
// The three shapes in which Nextcloud refuses the credentials - HTTP 401, and
// OCS 403 or 997 carried in the body - all return an error wrapping
// ErrNextcloudCredentialsRejected, so a caller can tell "this account cannot
// authenticate" from "Nextcloud is unreachable" and provision accordingly. Any
// other OCS code is an ordinary error.
//
// Which of the three shapes was returned is logged here, where it is still
// known: the caller collapses all three into one condition, so nothing further
// up can report the difference between a genuine rejection and a NEXTCLOUD_URL
// pointed at something that refuses for an unrelated reason.
func (c *NextcloudClient) MintAppToken(ctx context.Context, orcid, userPassword string) (string, error) {
	endpoint := c.URL + "/ocs/v2.php/core/getapppassword?format=json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("OCS-APIREQUEST", "true")
	req.Header.Set("User-Agent", NcMintUserAgent)
	req.SetBasicAuth(orcid, userPassword)

	client := &http.Client{Timeout: ncHTTPClientTimeout}
	if transport, _ := BuildTLSTransport(); transport != nil {
		client.Transport = transport
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		// Not logged per occurrence: HTTP 401 is exactly what Nextcloud answers
		// for an account that does not exist yet, so every brand-new user's
		// first mint arrives here and logging each one would bury the case that
		// matters in the case that does not.
		c.noteRejection(orcid, "HTTP 401")
		return "", ErrNextcloudCredentialsRejected
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		// Nextcloud is rate-limiting. This says nothing about which key is right;
		// retrying would double the load on a service that is already throttling.
		log.Printf("nc-mint: nextcloud rate-limited for %s (HTTP 429)", orcid)
		return "", ErrNextcloudRateLimited
	}

	var ocsResult OCSResponse
	if err := json.NewDecoder(resp.Body).Decode(&ocsResult); err != nil {
		return "", fmt.Errorf("decode OCS response: %w", err)
	}
	switch ocsResult.OCS.Meta.Statuscode {
	case 200:
		// fall through to the payload
	case 403, 997:
		// Nextcloud's in-band forms of the same rejection: HTTP 200 carrying a
		// credential failure. ocsAuthHints names both. All three shapes must
		// reach the caller as one condition, or a user whose Nextcloud emits
		// the unmapped one is stuck with no provisioning path - so the OCS code
		// that distinguishes them is recorded here, before that mapping.
		// Logged on sight, unlike HTTP 401: Nextcloud emits these only when it
		// actively refuses an existing context, so they are never the expected
		// answer for a new account and are anomalous whenever they appear. The
		// message is whatever NEXTCLOUD_URL returned, so it is quoted: an
		// unescaped newline in it would otherwise forge additional log lines.
		log.Printf("nc-mint: nextcloud refused the derived credentials for %s: OCS %d (%q)",
			orcid, ocsResult.OCS.Meta.Statuscode, ocsResult.OCS.Meta.Message)
		c.noteRejection(orcid, fmt.Sprintf("OCS %d", ocsResult.OCS.Meta.Statuscode))
		return "", fmt.Errorf("%w: %s", ErrNextcloudCredentialsRejected,
			formatOCSError("/core/getapppassword", ocsResult.OCS.Meta.Statuscode, ocsResult.OCS.Meta.Message, ocsAuthHints))
	default:
		return "", formatOCSError("/core/getapppassword", ocsResult.OCS.Meta.Statuscode, ocsResult.OCS.Meta.Message, ocsAuthHints)
	}
	data, ok := ocsResult.OCS.Data.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("unexpected OCS data format")
	}
	token, ok := data["apppassword"].(string)
	if !ok {
		return "", fmt.Errorf("apppassword not in response")
	}
	// This user's mint succeeded, so whatever refusals preceded it were the
	// ordinary first-login kind. Only their own streak is cleared: another
	// user's success says nothing about a user whose password has diverged.
	c.clearRejectionStreak(orcid)
	return token, nil
}

// noteRejection records one refused mint for orcid and reports that user's run
// once it is long enough to be something other than a first login.
//
// The threshold is crossed exactly once per streak, so a user who can never
// authenticate is reported once rather than on every request, and one
// successful mint by that user resets it. shape names which refusal Nextcloud
// returned, so the alert carries the detail the per-occurrence lines would have.
func (c *NextcloudClient) noteRejection(orcid, shape string) {
	c.rejectionStreaksMu.Lock()
	if c.rejectionStreaks == nil || len(c.rejectionStreaks) >= ncRejectionStreakMaxTracked {
		c.rejectionStreaks = make(map[string]int)
	}
	c.rejectionStreaks[orcid]++
	streak := c.rejectionStreaks[orcid]
	c.rejectionStreaksMu.Unlock()

	if streak != ncRejectionStreakAlertThreshold {
		return
	}
	log.Printf("nc-mint: %d consecutive credential rejections for %s with no successful mint "+
		"(most recent: %s) - check that NEXTCLOUD_URL points at Nextcloud, and that this "+
		"account's password matches what NC_DERIVATION_KEY derives (provisioning cannot "+
		"reset an existing account's password)",
		ncRejectionStreakAlertThreshold, orcid, shape)
}

// clearRejectionStreak forgets orcid's run of refusals. Deleting from a nil map
// is a no-op, so a client that has never seen a rejection needs no special case.
func (c *NextcloudClient) clearRejectionStreak(orcid string) {
	c.rejectionStreaksMu.Lock()
	delete(c.rejectionStreaks, orcid)
	c.rejectionStreaksMu.Unlock()
}

// HandleNcToken returns an HTTP handler for GET /internal/nc-token?orcid=<X>.
// It requires header X-ID1-Internal-Secret to match internalSecret.
//
// The handler mints only. It does NOT create the Nextcloud account: that is
// /internal/nc-provision's job, on its own wider budget. When Nextcloud
// refuses the derived password - the account does not exist, or its password
// diverged from the derivation key - the handler answers 409 with
// {"error":"nextcloud_credentials_rejected"} so the caller can provision and
// retry once rather than treating it as an outage.
//
// id1 registers no server-side ReadTimeout or WriteTimeout, so the handler
// bounds itself with timeout rather than relying on the caller's socket.
//
// The handler is stateless: it derives the user's Nextcloud login password
// from (orcid, derivationKey) and mints a fresh app token. id1 persists
// nothing - the caller caches.
//
// previousKeys carries the derivation keys a rotation has superseded but whose
// passwords some accounts still hold, newest first. Rotation resets each
// account's Nextcloud password to the current key's derivation one account at a
// time, so for the duration of that pass the two sides of the boundary need
// different keys; without the fallback every account not yet reset is refused
// and the outage scales with the user count. Each key is tried in turn and only
// while Nextcloud is REFUSING the credentials: a timeout or any other failure
// says nothing about which key is right, so retrying on those would double the
// load on a Nextcloud that is already failing. Passing no previousKeys is the
// steady state and behaves exactly as before.
func HandleNcToken(nc *NextcloudClient, derivationKey []byte, internalSecret string, timeout time.Duration, previousKeys ...[]byte) http.HandlerFunc {
	// Built once at construction rather than per request. The current key is
	// always index 0, which is what makes "current first" a property of the
	// data rather than of the loop body.
	keys := append([][]byte{derivationKey}, previousKeys...)
	return func(w http.ResponseWriter, r *http.Request) {
		if !secretMatches(r.Header.Get("X-ID1-Internal-Secret"), internalSecret) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		orcid := r.URL.Query().Get("orcid")
		if orcid == "" {
			http.Error(w, "orcid required", http.StatusBadRequest)
			return
		}
		if !orcidPattern.MatchString(orcid) {
			http.Error(w, "malformed orcid", http.StatusBadRequest)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()

		// One budget covers every attempt. A per-attempt timeout would let a
		// slow Nextcloud hold the caller for the sum of them.
		// Note: each failed attempt (when current key is rejected before trying
		// previous key) counts against Nextcloud's brute-force protection, doubling
		// the failed-login rate during rotation. A throttled Nextcloud will return
		// HTTP 429, which MintAppToken detects and returns ErrNextcloudRateLimited.
		// This is a known cost of the fallback during the rotation window.
		var token string
		var err error
		for _, key := range keys {
			var pw string
			pw, err = DeriveNextcloudPassword(key, orcid)
			if err != nil {
				http.Error(w, "derive failed", http.StatusInternalServerError)
				return
			}
			token, err = nc.MintAppToken(ctx, orcid, pw)
			if !errors.Is(err, ErrNextcloudCredentialsRejected) {
				// Success, or a failure that no other key can fix.
				break
			}
		}
		if err != nil {
			switch {
			case errors.Is(err, ErrNextcloudCredentialsRejected):
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusConflict)
				fmt.Fprint(w, `{"error":"nextcloud_credentials_rejected"}`)
			case errors.Is(err, ErrNextcloudRateLimited):
				http.Error(w, "nextcloud rate limited", http.StatusServiceUnavailable)
			case errors.Is(err, context.DeadlineExceeded):
				http.Error(w, "nextcloud timeout", http.StatusGatewayTimeout)
			case errors.Is(err, context.Canceled):
				// The caller hung up. There is no connection left to answer and
				// nothing has gone wrong with Nextcloud, so say nothing rather
				// than log a false outage on every abandoned request.
			default:
				fmt.Printf("nc-token: MintAppToken failed for %s: %v\n", orcid, err)
				http.Error(w, "nextcloud unavailable", http.StatusBadGateway)
			}
			return
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"token":%q}`, token)
	}
}

// HandleNcProvision returns an HTTP handler for
// POST /internal/nc-provision?orcid=<X>. It requires header
// X-ID1-Internal-Secret to match internalSecret.
//
// It creates the Nextcloud account and nothing else, answering 204 on success.
// EnsureUserExists accepts OCS 102 ("already exists") as success, so the
// endpoint is idempotent and safe to fire on every new Curatorium user. It
// mints no app password: repeated calls create no credentials.
//
// Account creation is slow, so this handler carries a far wider budget than
// minting. id1 registers no server-side ReadTimeout or WriteTimeout, so the
// handler bounds itself with timeout rather than relying on the caller's
// socket.
func HandleNcProvision(nc *NextcloudClient, derivationKey []byte, internalSecret string, timeout time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !secretMatches(r.Header.Get("X-ID1-Internal-Secret"), internalSecret) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		orcid := r.URL.Query().Get("orcid")
		if orcid == "" {
			http.Error(w, "orcid required", http.StatusBadRequest)
			return
		}
		if !orcidPattern.MatchString(orcid) {
			http.Error(w, "malformed orcid", http.StatusBadRequest)
			return
		}

		pw, err := DeriveNextcloudPassword(derivationKey, orcid)
		if err != nil {
			http.Error(w, "derive failed", http.StatusInternalServerError)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()

		if err := nc.EnsureUserExists(ctx, orcid, pw); err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				http.Error(w, "nextcloud timeout", http.StatusGatewayTimeout)
				return
			}
			if errors.Is(err, context.Canceled) {
				// The caller hung up. There is no connection left to answer and
				// nothing has gone wrong with Nextcloud, so say nothing rather
				// than log a false outage. The eager background provisioning
				// hook abandons requests routinely at backend shutdown.
				return
			}
			fmt.Printf("nc-provision: EnsureUserExists failed for %s: %v\n", orcid, err)
			http.Error(w, "nextcloud unavailable", http.StatusBadGateway)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// DeriveNextcloudPassword returns a deterministic Nextcloud login password for
// an ORCID user, computed as "NC_" + base64url(HMAC-SHA256(derivationKey, orcid)).
// The NC_ prefix ensures the derived value satisfies Nextcloud's password
// character-class requirements (upper + lower + digit + special).
//
// `curatorium admin nextcloud rotate-derivation-key` MUST produce byte-identical
// output for the same (key, orcid). Any divergence silently breaks every user
// on rotation.
func DeriveNextcloudPassword(derivationKey []byte, orcid string) (string, error) {
	if len(derivationKey) == 0 {
		return "", fmt.Errorf("derivation key must not be empty")
	}
	if orcid == "" {
		return "", fmt.Errorf("orcid must not be empty")
	}
	mac := hmac.New(sha256.New, derivationKey)
	mac.Write([]byte(orcid))
	digest := mac.Sum(nil)
	return "NC_" + base64.RawURLEncoding.EncodeToString(digest), nil
}

// __END_OF_FILE_MARKER__
