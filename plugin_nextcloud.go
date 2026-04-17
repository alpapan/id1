package id1

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// orcidPattern matches the standard ORCID iD format: XXXX-XXXX-XXXX-XXXX
// where X is a digit (last character may also be 'X' checksum).
var orcidPattern = regexp.MustCompile(`^\d{4}-\d{4}-\d{4}-\d{3}[\dX]$`)

// NextcloudProvisioner handles asynchronous Nextcloud user provisioning.
// It polls the id1 key store for new public key registrations and creates
// Nextcloud accounts with app passwords for each new ORCID identity.
type NextcloudProvisioner struct {
	nextcloudURL  string
	username      string
	password      string
	provisionedMu sync.Mutex
	provisioned   map[string]bool
	backoffUntil  map[string]time.Time  // per-user backoff expiry
	failCount     map[string]int        // per-user consecutive failure count
}

// NewNextcloudProvisioner creates a new NextcloudProvisioner from environment variables.
// Requires NC_PROVISIONER_USER and NC_PROVISIONER_PASSWORD.
func NewNextcloudProvisioner() *NextcloudProvisioner {
	return &NextcloudProvisioner{
		nextcloudURL: os.Getenv("NEXTCLOUD_URL"),
		username:     os.Getenv("NC_PROVISIONER_USER"),
		password:     os.Getenv("NC_PROVISIONER_PASSWORD"),
		provisioned:  make(map[string]bool),
		backoffUntil: make(map[string]time.Time),
		failCount:    make(map[string]int),
	}
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

// StartProvisioner begins the background polling loop that scans for new
// key registrations and provisions Nextcloud accounts.
func (p *NextcloudProvisioner) StartProvisioner() {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		// Run once at startup to catch any users that were registered
		// before the provisioner was started.
		p.scanAndProvision()
		for range ticker.C {
			p.scanAndProvision()
		}
	}()
}

// scanAndProvision scans the database for ORCID identities that have
// registered public keys but haven't been provisioned with Nextcloud yet.
func (p *NextcloudProvisioner) scanAndProvision() {
	// List all ORCID IDs by listing children of the root.
	// Each ORCID ID is a top-level directory in the key store.
	entries, err := os.ReadDir(dbpath)
	if err != nil {
		fmt.Printf("NextcloudProvisioner: failed to scan dbpath: %v\n", err)
		return
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		orcidId := entry.Name()

		// Skip service accounts and other non-ORCID identities.
		if !orcidPattern.MatchString(orcidId) {
			continue
		}

		// Skip if already provisioned in this session.
		p.provisionedMu.Lock()
		if p.provisioned[orcidId] {
			p.provisionedMu.Unlock()
			continue
		}
		p.provisionedMu.Unlock()

		// Skip if in backoff period after prior failure.
		p.provisionedMu.Lock()
		if until, ok := p.backoffUntil[orcidId]; ok && time.Now().Before(until) {
			p.provisionedMu.Unlock()
			continue
		}
		p.provisionedMu.Unlock()

		// Idempotency check: if nc-token already exists, skip provisioning.
		// This makes the provisioner safe to re-run after pod restart.
		tokenKey := KK(orcidId, "priv", "nc-token")
		tokenKeyPath := filepath.Join(dbpath, tokenKey.String())
		if _, err := os.Stat(tokenKeyPath); err == nil {
			// Token exists, mark as provisioned.
			p.provisionedMu.Lock()
			p.provisioned[orcidId] = true
			p.provisionedMu.Unlock()
			continue
		}

		// Check if this ORCID ID has any device key registered.
		pubKeysDir := filepath.Join(dbpath, orcidId, "pub", "keys")
		entries, err := os.ReadDir(pubKeysDir)
		if err != nil || len(entries) == 0 {
			continue
		}

		// Found an unprovisioned user with a public key.
		fmt.Printf("NextcloudProvisioner: provisioning user %s\n", orcidId)
		if err := p.provisionUser(orcidId); err != nil {
			fmt.Printf("NextcloudProvisioner: failed to provision %s: %v\n", orcidId, err)
			p.provisionedMu.Lock()
			if p.failCount != nil {
				p.failCount[orcidId]++
			}
			if p.backoffUntil != nil && p.failCount != nil {
				// Exponential: 2^0=1m, 2^1=2m, 2^2=4m, 2^3=8m, 2^4=16m, 2^5+=30m cap
				delay := time.Duration(1<<min(p.failCount[orcidId]-1, 5)) * time.Minute
				if delay > 30*time.Minute {
					delay = 30 * time.Minute
				}
				p.backoffUntil[orcidId] = time.Now().Add(delay)
				fmt.Printf("NextcloudProvisioner: backing off %s for %v (attempt %d)\n", orcidId, delay, p.failCount[orcidId])
			}
			p.provisionedMu.Unlock()
			continue
		}

		p.provisionedMu.Lock()
		p.provisioned[orcidId] = true
		delete(p.backoffUntil, orcidId)
		delete(p.failCount, orcidId)
		p.provisionedMu.Unlock()
	}
}

// provisionUser creates a Nextcloud user and generates an app password,
// then stores the app password in the id1 key store.
func (p *NextcloudProvisioner) provisionUser(orcidId string) error {
	// Load or generate password. On retry after partial failure, the staging
	// password already exists — reuse it so createAppPassword authenticates
	// with the same password that createUser originally stored in Nextcloud.
	stagingKey := KK(orcidId, "priv", "nc-staging-password")
	stagingPath := filepath.Join(dbpath, stagingKey.String())

	var initialPassword string
	if data, err := os.ReadFile(stagingPath); err == nil && len(data) > 0 {
		initialPassword = string(data)
	} else {
		initialPassword = generateRandomPassword()
		if initialPassword == "" {
			return fmt.Errorf("failed to generate initial password")
		}
		// Persist before any Nextcloud call — crash-safe.
		dir := filepath.Dir(stagingPath)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("failed to create staging dir: %w", err)
		}
		if err := os.WriteFile(stagingPath, []byte(initialPassword), 0o600); err != nil {
			return fmt.Errorf("failed to persist staging password: %w", err)
		}
	}

	if err := p.createUser(orcidId, initialPassword); err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	appPassword, err := p.createAppPassword(orcidId, initialPassword)
	if err != nil {
		return fmt.Errorf("failed to create app password: %w", err)
	}

	tokenKey := KK(orcidId, "priv", "nc-token")
	if _, err := CmdSet(tokenKey, map[string]string{"x-id": orcidId}, []byte(appPassword)).Exec(); err != nil {
		return fmt.Errorf("failed to persist nc-token for %s: %w", orcidId, err)
	}

	// Clean up staging password after successful provisioning.
	if err := os.Remove(stagingPath); err != nil && !os.IsNotExist(err) {
		fmt.Printf("NextcloudProvisioner: warning: failed to clean up staging password for %s: %v\n", orcidId, err)
	}

	return nil
}

// createUser creates a Nextcloud user via the OCS API.
// If the user already exists (OCS 102), this is treated as success
// to make the provisioner idempotent after pod restart.
func (p *NextcloudProvisioner) createUser(userId, password string) error {
	endpoint := p.nextcloudURL + "/ocs/v2.php/cloud/users?format=json"
	formData := url.Values{
		"userid":   {userId},
		"password": {password},
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(formData.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("OCS-APIREQUEST", "true")
	req.SetBasicAuth(p.username, p.password)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 30 * time.Second}
	if transport, _ := BuildTLSTransport(); transport != nil {
		client.Transport = transport
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	var ocsResult OCSResponse
	if err := json.NewDecoder(resp.Body).Decode(&ocsResult); err != nil {
		return fmt.Errorf("failed to parse OCS response: %w", err)
	}

	// OCS status codes: 100 = success, 102 = user already exists (idempotent).
	// OCS 200 is NOT a valid success code for user creation.
	switch ocsResult.OCS.Meta.Statuscode {
	case 100, 102:
		// 100 = success, 102 = user already exists (treat as success for idempotency)
		return nil
	default:
		return fmt.Errorf("OCS error %d: %s", ocsResult.OCS.Meta.Statuscode, ocsResult.OCS.Meta.Message)
	}
}

// createAppPassword creates an app-specific password for a Nextcloud user
// via the OCS API. The user authenticates with their own credentials
// (BasicAuth as orcidId:initialPassword).
func (p *NextcloudProvisioner) createAppPassword(userId, password string) (string, error) {
	endpoint := p.nextcloudURL + "/ocs/v2.php/core/getapppassword?format=json"
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("OCS-APIREQUEST", "true")
	req.SetBasicAuth(userId, password)

	client := &http.Client{Timeout: 30 * time.Second}
	if transport, _ := BuildTLSTransport(); transport != nil {
		client.Transport = transport
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	var ocsResult OCSResponse
	if err := json.NewDecoder(resp.Body).Decode(&ocsResult); err != nil {
		return "", fmt.Errorf("failed to parse OCS response: %w", err)
	}

	// OCS status code 200 = success for getapppassword endpoint.
	// This differs from user creation which uses 100.
	if ocsResult.OCS.Meta.Statuscode != 200 {
		return "", fmt.Errorf("getapppassword OCS error %d: %s", ocsResult.OCS.Meta.Statuscode, ocsResult.OCS.Meta.Message)
	}

	// Extract app password from response data.
	data, ok := ocsResult.OCS.Data.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("unexpected OCS data format")
	}

	appPassword, ok := data["apppassword"].(string)
	if !ok {
		return "", fmt.Errorf("apppassword not found in response")
	}

	return appPassword, nil
}

// generateRandomPassword generates a cryptographically secure random password
// encoded as URL-safe base64. Returns empty string on error.
func generateRandomPassword() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return fmt.Sprintf("NC_%s", strings.TrimRight(base64.URLEncoding.EncodeToString(b), "="))
}

// __END_OF_FILE_MARKER__
