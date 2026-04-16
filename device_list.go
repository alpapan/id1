package id1

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// DeviceInfo represents a single registered device.
type DeviceInfo struct {
	DeviceId   string `json:"deviceId"`
	DeviceName string `json:"deviceName"`
}

// DeviceListResponse is returned by GET /auth/sovereign/devices.
type DeviceListResponse struct {
	Devices []DeviceInfo `json:"devices"`
}

// HandleListDevices returns an HTTP handler that lists all registered devices
// for the authenticated user.
//
// Endpoint: GET /auth/sovereign/devices?id={orcidId}
// Auth: RS256 JWT required (user can only list their own devices)
func HandleListDevices(kvStore KeyValueStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cors(&w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		orcidId := r.URL.Query().Get("id")
		if orcidId == "" {
			http.Error(w, "Missing id parameter", http.StatusBadRequest)
			return
		}

		// Require RS256 JWT
		claims, err := extractAndValidateJWT(r, kvStore)
		if err != nil {
			http.Error(w, "Authorization required", http.StatusUnauthorized)
			return
		}
		if claims.Subject != orcidId {
			http.Error(w, "Cannot list devices for another user", http.StatusForbidden)
			return
		}

		// Read pub/keys/ directory
		keysDir := filepath.Join(dbpath, orcidId, "pub", "keys")
		entries, err := os.ReadDir(keysDir)
		if err != nil {
			// No keys directory — return empty list
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(DeviceListResponse{Devices: []DeviceInfo{}})
			return
		}

		var devices []DeviceInfo
		for _, entry := range entries {
			if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") || strings.HasSuffix(entry.Name(), ".name") {
				continue
			}
			deviceId := entry.Name()
			deviceName := deviceId // default to ID
			if nameData, err := CmdGet(KK(orcidId, "pub", "keys", deviceId+".name")).Exec(); err == nil {
				deviceName = string(nameData)
			}
			devices = append(devices, DeviceInfo{DeviceId: deviceId, DeviceName: deviceName})
		}

		if devices == nil {
			devices = []DeviceInfo{}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(DeviceListResponse{Devices: devices})
	}
}

// HandleDeleteDevice returns an HTTP handler that revokes a specific device
// for the authenticated user.
//
// Endpoint: DELETE /auth/sovereign/devices?id={orcidId}&device={deviceId}
// Auth: RS256 JWT required (user can only revoke their own devices)
func HandleDeleteDevice(kvStore KeyValueStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cors(&w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method != http.MethodDelete {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		orcidId := r.URL.Query().Get("id")
		deviceId := r.URL.Query().Get("device")
		if orcidId == "" || deviceId == "" {
			http.Error(w, "Missing id or device parameter", http.StatusBadRequest)
			return
		}

		// Require RS256 JWT
		claims, err := extractAndValidateJWT(r, kvStore)
		if err != nil {
			http.Error(w, "Authorization required", http.StatusUnauthorized)
			return
		}
		if claims.Subject != orcidId {
			http.Error(w, "Cannot revoke devices for another user", http.StatusForbidden)
			return
		}

		// Delete the device key and its name metadata
		CmdDel(KK(orcidId, "pub", "keys", deviceId)).Exec()
		CmdDel(KK(orcidId, "pub", "keys", deviceId+".name")).Exec()

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"deleted","deviceId":"%s"}`, deviceId)
	}
}

type deviceJWTClaims struct {
	Subject string
}

// extractAndValidateJWT extracts a Bearer token from the Authorization header
// and validates it as an RS256 JWT signed by id1.
func extractAndValidateJWT(r *http.Request, kvStore KeyValueStore) (deviceJWTClaims, error) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return deviceJWTClaims{}, fmt.Errorf("missing Bearer token")
	}
	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

	claims, err := ValidateRS256JWT(tokenStr, kvStore)
	if err != nil {
		return deviceJWTClaims{}, err
	}

	return deviceJWTClaims{Subject: claims.Subject}, nil
}
