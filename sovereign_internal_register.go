package id1

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"regexp"
)

// devicePattern bounds the device (curatorium) id to a safe single key segment. It
// must START with an alphanumeric, which rejects "."/".."/leading-dot segments that
// could otherwise walk the key path (belt-and-suspenders alongside keyWithinRoot).
var devicePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// InternalRegisterRequest is the JSON body for POST /internal/sovereign/register.
type InternalRegisterRequest struct {
	ID           string `json:"id"`
	Device       string `json:"device"`
	PublicKeyPEM string `json:"publicKeyPem"`
}

// HandleInternalRegisterKey returns an HTTP handler for POST /internal/sovereign/register.
//
// Trusted-provisioner endpoint authenticated by mutual TLS: the caller's credential
// is its client certificate (never a transmitted secret). It writes - and OVERWRITES -
// the per-curatorium device key {id}/pub/keys/{device}, so one shared ORCID carries a
// distinct key per curatorium and the same call serves provision, rotation, and the
// lazy re-register-on-miss path.
//
// Gate: a CA-verified client cert is required (r.TLS.VerifiedChains non-empty; with
// ClientAuth=VerifyClientCertIfGiven a no-cert client connects with empty chains and a
// non-CA cert fails the handshake), AND the request device must equal the cert CN - the
// CN is the tenant boundary, so a curatorium can only register under its own device slot.
//
// main.go_ mounts this ONLY when INTERNAL_REGISTER_ENABLED=true - i.e. on the dedicated
// annot8r_id1 whose SSL_CA_CERTS is a dedicated CA. It is NOT mounted on curatorium's own
// id1 (broad in-cluster CA). It is also inert without TLS (r.TLS==nil -> 401).
func HandleInternalRegisterKey() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			http.Error(w, "client certificate required", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Cap the body: it is a small JSON {id, device, publicKeyPem}; bound it so a
		// trusted-but-buggy (or compromised) caller cannot stream an oversized body.
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10) // 64 KiB

		var req InternalRegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		if req.ID == "" || !orcidPattern.MatchString(req.ID) {
			http.Error(w, "missing or malformed id", http.StatusBadRequest)
			return
		}
		if req.Device == "" || !devicePattern.MatchString(req.Device) {
			http.Error(w, "missing or malformed device", http.StatusBadRequest)
			return
		}
		// CN-pin: the client may only register under its own curatorium id. The cert
		// CN is the tenant boundary; a curatorium cannot write another's device slot.
		cn := r.TLS.VerifiedChains[0][0].Subject.CommonName
		if req.Device != cn {
			http.Error(w, "device does not match client certificate CN", http.StatusForbidden)
			return
		}
		if req.PublicKeyPEM == "" {
			http.Error(w, "Missing publicKeyPem", http.StatusBadRequest)
			return
		}
		if err := validateRSAPublicKeyPEM(req.PublicKeyPEM); err != nil {
			http.Error(w, "Invalid public key: "+err.Error(), http.StatusBadRequest)
			return
		}

		// Per-curatorium device key. CmdSet overwrites any existing value at the slot.
		if _, err := CmdSet(KK(req.ID, "pub", "keys", req.Device), map[string]string{"x-id": req.ID}, []byte(req.PublicKeyPEM)).Exec(); err != nil {
			http.Error(w, "Failed to store key", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"registered","id":%q,"device":%q}`, req.ID, req.Device)
	}
}

// validateRSAPublicKeyPEM returns nil iff pemStr is a PEM-encoded RSA public key
// (PKIX "PUBLIC KEY" or PKCS#1 "RSA PUBLIC KEY"). Rejecting non-RSA/garbage here
// surfaces a bad key at provision time rather than as a silent mint failure later.
func validateRSAPublicKeyPEM(pemStr string) error {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return fmt.Errorf("not PEM-encoded")
	}
	if pub, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		if _, ok := pub.(*rsa.PublicKey); !ok {
			return fmt.Errorf("not an RSA public key")
		}
		return nil
	}
	if _, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return nil
	}
	return fmt.Errorf("unparseable public key")
}
