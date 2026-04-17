package id1

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
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

// formatOCSError returns a diagnostic error wrapping (code, message, hint).
// hints is the applicable code→hint map (provisioning vs auth).
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

// NextcloudClient is a minimal HTTP client for Nextcloud's OCS API.
// It is stateless apart from its configured admin credentials and is safe
// to share across goroutines (no mutable state once constructed).
type NextcloudClient struct {
	URL      string
	Username string
	Password string
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

	client := &http.Client{Timeout: 30 * time.Second}
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
// app token. Expects OCS statuscode 200 for success.
func (c *NextcloudClient) MintAppToken(ctx context.Context, orcid, userPassword string) (string, error) {
	endpoint := c.URL + "/ocs/v2.php/core/getapppassword?format=json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("OCS-APIREQUEST", "true")
	req.SetBasicAuth(orcid, userPassword)

	client := &http.Client{Timeout: 30 * time.Second}
	if transport, _ := BuildTLSTransport(); transport != nil {
		client.Transport = transport
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return "", fmt.Errorf("Nextcloud rejected credentials (401)")
	}

	var ocsResult OCSResponse
	if err := json.NewDecoder(resp.Body).Decode(&ocsResult); err != nil {
		return "", fmt.Errorf("decode OCS response: %w", err)
	}
	if ocsResult.OCS.Meta.Statuscode != 200 {
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
	return token, nil
}

// HandleNcToken returns an HTTP handler for GET /internal/nc-token?orcid=<X>.
// It requires header X-ID1-Internal-Secret to match the configured secret.
// On success, returns 200 with JSON {"token": "<plaintext app password>"}.
//
// The handler is stateless: on each call it derives the user's Nextcloud login
// password from (orcid, derivationKey), ensures the user exists, and mints a
// fresh app token. id1 does not persist the result — the caller (backend) is
// responsible for caching.
func HandleNcToken(nc *NextcloudClient, derivationKey []byte, internalSecret string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-ID1-Internal-Secret") != internalSecret {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
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

		ctx := r.Context()
		if err := nc.EnsureUserExists(ctx, orcid, pw); err != nil {
			fmt.Printf("nc-token: EnsureUserExists failed for %s: %v\n", orcid, err)
			http.Error(w, "nextcloud unavailable", http.StatusBadGateway)
			return
		}
		token, err := nc.MintAppToken(ctx, orcid, pw)
		if err != nil {
			fmt.Printf("nc-token: MintAppToken failed for %s: %v\n", orcid, err)
			http.Error(w, "nextcloud unavailable", http.StatusBadGateway)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"token":%q}`, token)
	}
}

// DeriveNextcloudPassword returns a deterministic Nextcloud login password for
// an ORCID user, computed as "NC_" + base64url(HMAC-SHA256(derivationKey, orcid)).
// The NC_ prefix ensures the derived value satisfies Nextcloud's password
// character-class requirements (upper + lower + digit + special).
//
// The bash rotation script (ops/host-cron/curatorium-rotate-nc-key.sh) MUST produce
// byte-identical output for the same (key, orcid). Any divergence silently breaks
// every user on rotation.
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
