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
	101: "invalid input (check userid format and password policy; Nextcloud also answers 101 when a concurrent request created the same user first)",
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
// login password. Normally it means the account exists with a password that no
// longer matches what the derivation key produces. The account not existing
// also produces it, but only for a caller that has not read existence first;
// HandleNcToken reads it first. Neither is recoverable by minting alone.
var ErrNextcloudCredentialsRejected = errors.New("nextcloud rejected the derived credentials")
var ErrNextcloudRateLimited = errors.New("nextcloud is rate-limiting requests")

// ncThrottleRecovery is appended to every log line reporting that Nextcloud
// answered HTTP 429. Nextcloud's brute-force protection records failed logins
// against the caller's address, and a throttled address is refused before its
// credentials are checked, so no successful login can clear the recorded
// attempts. Repairing the credential that caused the failures therefore leaves
// this caller throttled until the recorded attempts age out or an operator
// clears them. Without the command named here, an operator who has fixed the
// credential sees the throttle persist and concludes the fix did not work.
const ncThrottleRecovery = "Nextcloud brute-force protection is throttling the id1 pod's IP address; " +
	"repairing the credential does not clear it - clear it by running " +
	"php occ security:bruteforce:reset ID1_POD_IP in the Nextcloud pod, " +
	"with ID1_POD_IP replaced by the id1 pod's IP address"

// ocsUserLookupHints maps the OCS statuscodes Nextcloud's single-user read
// (GET /cloud/users/{userid}) can answer, other than success and 404, to hints.
// 998 is what UsersController answers when the calling account has no rights
// over the target user: the provisioning account has lost its admin group,
// which is a fault in id1's own configuration, never evidence that the user is
// missing.
var ocsUserLookupHints = map[int]string{
	997: "unauthorised (the provisioning account's credentials were refused - check NC_PROVISIONER_USER and NC_PROVISIONER_PASSWORD)",
	998: "user not visible to the provisioning account (NC_PROVISIONER_USER must be in Nextcloud's admin group)",
}

// ncPasswordBlockCooldown is how long id1 attempts no login for a user whose
// existing Nextcloud account refused every derivation key. Nextcloud's
// brute-force protection counts failed logins per caller address over a
// 30-minute window (auth.bruteforce.max-attempts, default 10), and id1 is one
// address for every user, so each further attempt for an account that cannot
// authenticate spends a budget that every other user's logins draw on. No
// login can succeed while the block holds, because the block skips the login
// itself: it lifts only when the cooldown expires, so a user whose password is
// repaired stays refused for up to this long.
const ncPasswordBlockCooldown = 30 * time.Minute

// ncPasswordBlockMaxTracked bounds the password-block table. Entries are
// removed once their cooldown has passed, so it holds only users currently
// blocked - normally none. Past the bound, lifted blocks are dropped first and
// then the block that lifts soonest, one ORCID at a time, so the table stays
// bounded without ever releasing every block at once.
const ncPasswordBlockMaxTracked = 10000

// ncNow is the clock the password block reads. A package variable rather than
// direct time.Now calls so a test can move time past the cooldown without
// sleeping through it.
var ncNow = time.Now

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

// NcTokenTimeout bounds the mint-only token handler. One shared budget covers
// every Nextcloud round trip a request makes. In the steady state that is two:
// the provisioning account's existence read, then one token request (~1.24s
// for a token request against a healthy Nextcloud). During a rotation it is
// one further token request per armed previous derivation key, so three with
// one previous key. A missing account is answered 409 by the existence read
// alone, with no login as the user, so it never reaches a token request. The
// budget must stay strictly smaller than ncHTTPClientTimeout (30s) so socket
// timeouts do not hide handler timeouts, and strictly smaller than
// NcProvisionTimeout so provisioning keeps the wider budget.
//
// The budget must exceed the time a busy Nextcloud takes to answer one read, or
// the handler answers 504 for a lookup that would have succeeded. The caller's
// own client timeout for this call must stay above this budget, so id1's 504
// surfaces rather than a client-side timeout that hides which side gave up.
//
// Edge case: if a slow existence read or token request exhausts the shared
// budget, the handler answers 504, and the caller's provisioning path
// (nextcloud_credentials.py in the backend) provisions only on 409, so a 504
// never itself triggers provisioning. This is accepted rather than sized
// against len(keys) round trips because the rotation window, when Nextcloud is
// also mid password-reset pass, is transient.
const NcTokenTimeout = 20 * time.Second

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
// hints is the applicable code->hint map (provisioning vs auth). message is
// whatever Nextcloud's OCS response returned, so it is quoted (%q, not %s):
// this error is logged verbatim wherever it surfaces, and an unescaped
// embedded newline would otherwise forge additional log lines.
func formatOCSError(endpoint string, code int, message string, hints map[int]string) error {
	if hint, ok := hints[code]; ok {
		return fmt.Errorf("OCS error %d at %s: %q (%s)", code, endpoint, message, hint)
	}
	return fmt.Errorf("OCS error %d at %s: %q", code, endpoint, message)
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
// reported. HandleNcToken reads account existence first and mints only for an
// account that exists, so a rejection normally means an existing account whose
// password has diverged from the derivation key; a missing account reaches a
// mint only in a race (deleted between the read and the mint) or through a
// caller that skips the existence read. A user refused over and over is
// reported whether the cause is that divergence or a misaimed NEXTCLOUD_URL.
// Provisioning cannot repair either, so nothing else would ever report it.
const ncRejectionStreakAlertThreshold = 5

// ncRejectionStreakMaxTracked bounds the streak table. Entries are removed on a
// successful mint, so it holds only users currently being refused - normally
// none. The cap covers the pathological case where Nextcloud refuses everyone:
// the table is diagnostic state only, so past the cap it is simply dropped,
// which costs at worst a delayed alert.
const ncRejectionStreakMaxTracked = 10000

// NextcloudClient is a minimal HTTP client for Nextcloud's OCS API. It is safe
// to share across goroutines: its configuration is fixed once constructed, and
// its three pieces of mutable state - the per-user mint-rejection streaks used
// for a misconfiguration alert, the per-ORCID provisioning locks used to
// serialise concurrent provisioning attempts, and the per-ORCID password
// blocks that stop logins for an account refusing every derivation key - are
// each guarded by their own mutex.
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

	// provisionLocks holds one entry per ORCID with a provisioning attempt
	// currently in flight against this client. Nextcloud's provisioning_api
	// UsersController::addUser checks userExists then calls createUser with no
	// transactional protection between the two, so two callers racing the same
	// ORCID can both pass the existence check before either commits the insert;
	// the loser's insert then fails with a unique-constraint violation, which
	// Nextcloud reports as OCS 101 ("invalid input") rather than the idempotent
	// 102 EnsureUserExists already treats as success. Holding the per-ORCID
	// mutex for the duration of a provisioning attempt guarantees the second
	// caller's HTTP request to Nextcloud starts only after the first one has
	// returned, so it never races the first one's insert (whatever the first
	// one's own outcome was). Entries are reference-counted and deleted once
	// no request for that ORCID is waiting or in flight, so the map holds at
	// most one entry per ORCID currently being provisioned, never one per
	// ORCID ever seen.
	provisionLocksMu sync.Mutex
	provisionLocks   map[string]*ncProvisionLock

	// passwordBlocks maps an ORCID to the instant its password block lifts.
	// An ORCID is entered when its account exists and refused every
	// derivation key, and HandleNcToken attempts no login for it until that
	// instant. Separate from rejectionStreaks, which only counts refusals for
	// an alert and is never read for control flow.
	passwordBlocksMu sync.Mutex
	passwordBlocks   map[string]time.Time
}

// ncProvisionLock is one ORCID's provisioning mutex plus the count of
// requests currently holding a reference to it, so the entry can be removed
// from NextcloudClient.provisionLocks the moment no request needs it any
// more.
type ncProvisionLock struct {
	mu   sync.Mutex
	refs int
}

// acquireProvisionLock returns the (possibly new) lock guarding provisioning
// attempts for orcid against this client, incrementing its reference count.
// The caller must call releaseProvisionLock exactly once, after unlocking, to
// balance this call.
func (c *NextcloudClient) acquireProvisionLock(orcid string) *ncProvisionLock {
	c.provisionLocksMu.Lock()
	defer c.provisionLocksMu.Unlock()
	if c.provisionLocks == nil {
		c.provisionLocks = make(map[string]*ncProvisionLock)
	}
	lock, ok := c.provisionLocks[orcid]
	if !ok {
		lock = &ncProvisionLock{}
		c.provisionLocks[orcid] = lock
	}
	lock.refs++
	return lock
}

// releaseProvisionLock unlocks lock and drops this caller's reference,
// removing orcid's entry from the map once no request holds or awaits it.
// Deleting is guarded by both the key and a pointer-identity check against
// the map's current value for it: the count reaching zero means no reference
// to lock itself remains outstanding, but only deleting the entry that still
// equals lock stops this call from ever discarding a different, newer entry
// that acquireProvisionLock may since have created under the same key.
func (c *NextcloudClient) releaseProvisionLock(orcid string, lock *ncProvisionLock) {
	c.provisionLocksMu.Lock()
	lock.refs--
	if lock.refs == 0 && c.provisionLocks[orcid] == lock {
		delete(c.provisionLocks, orcid)
	}
	c.provisionLocksMu.Unlock()
	lock.mu.Unlock()
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

	if resp.StatusCode == http.StatusTooManyRequests {
		// Nextcloud is throttling the id1 pod's address. The body is not an
		// OCS document, so decoding it would misreport throttling as a
		// malformed response and hide the one fact the operator needs.
		log.Printf("nc-provision: nextcloud rate-limited for %s (HTTP 429) - %s", orcid, ncThrottleRecovery)
		return ErrNextcloudRateLimited
	}

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
		// for an account that does not exist yet, and a caller that has not
		// read existence first arrives here on every brand-new user's first
		// mint; logging each one would bury the case that matters in the case
		// that does not. noteRejection reports a run of them instead.
		c.noteRejection(orcid, "HTTP 401")
		return "", ErrNextcloudCredentialsRejected
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		// Nextcloud is rate-limiting. This says nothing about which key is right;
		// retrying would double the load on a service that is already throttling.
		log.Printf("nc-mint: nextcloud rate-limited for %s (HTTP 429) - %s", orcid, ncThrottleRecovery)
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

// UserExists asks Nextcloud, as the provisioning account, whether an account
// named orcid exists. It reads GET /ocs/v2.php/cloud/users/{orcid} and decides
// on the OCS statuscode in the body, never the HTTP status alone, because
// Nextcloud serves both a missing user (OCS 404) and a provisioning account
// without rights over the user (OCS 998) as HTTP 404. Only OCS 404 means the
// account is missing; OCS 998 and every other code is an error. HTTP 429 is
// reported as ErrNextcloudRateLimited.
//
// The provisioning account's login succeeds, so the read adds nothing to
// Nextcloud's failed-login count, unlike a login as a user who does not exist.
func (c *NextcloudClient) UserExists(ctx context.Context, orcid string) (bool, error) {
	endpoint := c.URL + "/ocs/v2.php/cloud/users/" + url.PathEscape(orcid) + "?format=json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("OCS-APIREQUEST", "true")
	req.SetBasicAuth(c.Username, c.Password)

	client := &http.Client{Timeout: ncHTTPClientTimeout}
	if transport, _ := BuildTLSTransport(); transport != nil {
		client.Transport = transport
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		// Throttling, not an answer about the account. The body is not an OCS
		// document, so decoding it would hide the one fact the operator needs.
		log.Printf("nc-exists: nextcloud rate-limited for %s (HTTP 429) - %s", orcid, ncThrottleRecovery)
		return false, ErrNextcloudRateLimited
	}

	var ocsResult OCSResponse
	if err := json.NewDecoder(resp.Body).Decode(&ocsResult); err != nil {
		return false, fmt.Errorf("decode OCS response: %w", err)
	}
	switch ocsResult.OCS.Meta.Statuscode {
	case 100, 200:
		return true, nil
	case 404:
		return false, nil
	default:
		return false, formatOCSError("/cloud/users/{userid}", ocsResult.OCS.Meta.Statuscode, ocsResult.OCS.Meta.Message, ocsUserLookupHints)
	}
}

// passwordBlocked reports whether orcid is inside a password block. An entry
// whose cooldown has passed is removed here, so an ORCID leaves the table on
// its first request after the block lifts.
func (c *NextcloudClient) passwordBlocked(orcid string) bool {
	c.passwordBlocksMu.Lock()
	defer c.passwordBlocksMu.Unlock()
	until, ok := c.passwordBlocks[orcid]
	if !ok {
		return false
	}
	if ncNow().Before(until) {
		return true
	}
	delete(c.passwordBlocks, orcid)
	return false
}

// blockPassword starts orcid's password block, lasting ncPasswordBlockCooldown
// from now. When the table is full, blocks that have already lifted are
// dropped first; if it is still full, the block that lifts soonest is
// released, so the table stays bounded without clearing every block at once.
func (c *NextcloudClient) blockPassword(orcid string) {
	now := ncNow()
	c.passwordBlocksMu.Lock()
	defer c.passwordBlocksMu.Unlock()
	if c.passwordBlocks == nil {
		c.passwordBlocks = make(map[string]time.Time)
	}
	if _, present := c.passwordBlocks[orcid]; !present && len(c.passwordBlocks) >= ncPasswordBlockMaxTracked {
		for blocked, until := range c.passwordBlocks {
			if !now.Before(until) {
				delete(c.passwordBlocks, blocked)
			}
		}
		if len(c.passwordBlocks) >= ncPasswordBlockMaxTracked {
			soonest := ""
			var soonestUntil time.Time
			for blocked, until := range c.passwordBlocks {
				if soonest == "" || until.Before(soonestUntil) {
					soonest, soonestUntil = blocked, until
				}
			}
			delete(c.passwordBlocks, soonest)
		}
	}
	c.passwordBlocks[orcid] = now.Add(ncPasswordBlockCooldown)
}

// writeNcPasswordRejected answers 409 with the code that tells the caller the
// account exists but refuses every derivation key. The backend provisions only
// for nextcloud_credentials_rejected, so this code never creates an account.
func writeNcPasswordRejected(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusConflict)
	fmt.Fprint(w, `{"error":"nextcloud_password_rejected"}`)
}

// answerNcTokenFailure answers /internal/nc-token for a failure of step
// (UserExists or MintAppToken) that is not a credentials rejection.
func answerNcTokenFailure(w http.ResponseWriter, step, orcid string, err error) {
	switch {
	case errors.Is(err, ErrNextcloudRateLimited):
		http.Error(w, "nextcloud rate limited", http.StatusServiceUnavailable)
	case errors.Is(err, context.DeadlineExceeded):
		http.Error(w, "nextcloud timeout", http.StatusGatewayTimeout)
	case errors.Is(err, context.Canceled):
		// The caller hung up. There is no connection left to answer and
		// nothing has gone wrong with Nextcloud, so say nothing rather
		// than log a false outage on every abandoned request.
	default:
		fmt.Printf("nc-token: %s failed for %s: %v\n", step, orcid, err)
		http.Error(w, "nextcloud unavailable", http.StatusBadGateway)
	}
}

// HandleNcToken returns an HTTP handler for GET /internal/nc-token?orcid=<X>.
// It requires header X-ID1-Internal-Secret to match internalSecret.
//
// The handler mints only. It does NOT create the Nextcloud account: that is
// /internal/nc-provision's job, on its own wider budget. Before any login as
// the user it asks Nextcloud, as the provisioning account, whether the account
// exists, because Nextcloud records a login to a missing account as a failed
// login against id1's own address, which every user shares. Its two 409
// answers:
//
//   - {"error":"nextcloud_credentials_rejected"}: the account does not exist,
//     so the caller can provision and retry once. No login was attempted.
//   - {"error":"nextcloud_password_rejected"}: the account exists and refused
//     every derivation key. Provisioning cannot repair that, so the caller
//     must not provision. id1 then attempts no login for that ORCID until
//     ncPasswordBlockCooldown has passed, answering the same code meanwhile.
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

		// A user whose existing account refused every key is not logged in as
		// again until the cooldown expires: each attempt would be one more
		// failed login against id1's own address, shared with every user.
		if nc.passwordBlocked(orcid) {
			writeNcPasswordRejected(w)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()

		// Never log in as an account not known to exist: Nextcloud records that
		// as a failed login against id1's address, so a burst of brand-new users
		// would throttle id1 for everyone. The read shares this request's budget.
		exists, err := nc.UserExists(ctx, orcid)
		if err != nil {
			answerNcTokenFailure(w, "UserExists", orcid, err)
			return
		}
		if !exists {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			fmt.Fprint(w, `{"error":"nextcloud_credentials_rejected"}`)
			return
		}

		// One budget covers every attempt. A per-attempt timeout would let a
		// slow Nextcloud hold the caller for the sum of them.
		// Note: each failed attempt (when current key is rejected before trying
		// previous key) counts against Nextcloud's brute-force protection, doubling
		// the failed-login rate during rotation. A throttled Nextcloud will return
		// HTTP 429, which MintAppToken detects and returns ErrNextcloudRateLimited.
		// This is a known cost of the fallback during the rotation window.
		var token string
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
			if errors.Is(err, ErrNextcloudCredentialsRejected) {
				// The account exists, so provisioning cannot help: its password
				// differs from every key id1 holds. Stop logging in as it.
				nc.blockPassword(orcid)
				log.Printf("nc-token: the existing Nextcloud account %s refused every derivation key; "+
					"no login is attempted for it for %s - its password does not match what "+
					"NC_DERIVATION_KEY derives", orcid, ncPasswordBlockCooldown)
				writeNcPasswordRejected(w)
				return
			}
			answerNcTokenFailure(w, "MintAppToken", orcid, err)
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

		// Serialise by ORCID: a second concurrent provisioning request for the
		// same ORCID must run strictly after the first one returns, or it races
		// Nextcloud's own check-then-insert and gets OCS 101 instead of 102.
		// This closes the race between two requests id1 has in flight at once;
		// it cannot close a race against Nextcloud still finishing a createUser
		// server-side after id1 gave up waiting for its response (a caller
		// disconnect cancels ctx and this handler returns immediately, but
		// Nextcloud's PHP process is not guaranteed to have aborted). ctx's
		// deadline is fixed above, before this lock wait, so a queued request
		// counts its wait against its own NcProvisionTimeout budget rather than
		// getting a fresh one once the lock is free: if that budget is already
		// spent by the time the lock is acquired, EnsureUserExists sees an
		// already-expired ctx and answers 504 without another Nextcloud round
		// trip. A burst of concurrent requests for the same ORCID therefore
		// finishes within roughly one NcProvisionTimeout in total, not one per
		// queued request.
		lock := nc.acquireProvisionLock(orcid)
		lock.mu.Lock()
		defer nc.releaseProvisionLock(orcid, lock)

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
			if errors.Is(err, ErrNextcloudRateLimited) {
				// Already logged, with the recovery command, by EnsureUserExists.
				// Answered as /internal/nc-token answers it, so a caller sees one
				// status for throttling on either endpoint.
				http.Error(w, "nextcloud rate limited", http.StatusServiceUnavailable)
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
