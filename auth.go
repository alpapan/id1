// apps/backend/containers/id1/auth.go
//
// group: auth
// tags: authentication, authorization, ownership, permissions
// summary: Core authorization logic for key/value store operations.
// Evaluates command ownership, public access, and auth-dot-op directives.
//
//

package id1

import (
	"crypto/subtle"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// auth reports whether id may perform cmd. internalSecretHeader is the
// X-ID1-Internal-Secret header value from the originating HTTP request, when
// one is available; pass "" when there is no request context (e.g. the
// scheduled .after sweep in dot_after.go).
func auth(id string, cmd Command, internalSecretHeader string) bool {
	isOwner := cmd.Key.Id == id
	isPublicGet := cmd.Key.Pub && (cmd.Op == Get || cmd.Op == List)
	authorized := isOwner || isPublicGet || authDotOp(id, cmd)
	isNewIdClaim := !authorized && (cmd.Op == Set && cmd.Key.Pub && cmd.Key.Name == "key")
	exists := idExists(cmd.Key.Id)
	authorized = authorized || (isNewIdClaim && !exists && validInternalSecret(internalSecretHeader))
	return authorized
}

// validInternalSecret reports whether header matches the server's configured
// ID1_INTERNAL_SECRET. An unset (or empty) server-side secret never matches -
// not even against an empty header - so a misconfigured deployment fails
// closed (the bootstrap is refused) rather than degrading to an
// unauthenticated-allow. The comparison is constant-time to avoid leaking the
// secret's contents through a response-timing side channel.
func validInternalSecret(header string) bool {
	secret := os.Getenv("ID1_INTERNAL_SECRET")
	if secret == "" || header == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(header), []byte(secret)) == 1
}

func idExists(id string) bool {
	// Singular service-identity path: {id}/pub/key (bootstrapped via the
	// anonymous POST exemption below, read as a fallback by HandleSovereignToken).
	singularPath := filepath.Join(dbpath, id, "pub", "key")
	if info, err := os.Stat(singularPath); err == nil && !info.IsDir() {
		return true
	}
	// Multi-device ORCID path: {id}/pub/keys/{deviceId} files in a directory.
	keysDir := filepath.Join(dbpath, id, "pub", "keys")
	entries, err := os.ReadDir(keysDir)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if !entry.IsDir() && !strings.HasPrefix(entry.Name(), ".") && !strings.HasSuffix(entry.Name(), ".name") {
			return true
		}
	}
	return false
}

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

func validateToken(token, secret string) (Claims, error) {
	claims := Claims{}
	if jwtToken, err := jwt.ParseWithClaims(token, &claims, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	}); err != nil {
		return claims, err
	} else if !jwtToken.Valid {
		return claims, fmt.Errorf("invalid token")
	} else {
		return claims, nil
	}
}
