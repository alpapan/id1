// apps/id1/jwt_validation_claims_test.go
//
// group: jwt
// tags: jwt, rs256, audience, issuer, rotation, testing
// summary: Tests that the RS256 validators check audience, issuer and algorithm and accept the previous key.
//
//

package id1

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

// rs256Validators lists both exported validators behind one signature, so every
// test below holds each of them to the same rule.
var rs256Validators = []struct {
	name     string
	validate func(token string, kv KeyValueStore) error
}{
	{"ValidateRS256JWT", func(token string, kv KeyValueStore) error {
		_, err := ValidateRS256JWT(token, kv)
		return err
	}},
	{"ValidateRS256JWTID1Claims", func(token string, kv KeyValueStore) error {
		_, err := ValidateRS256JWTID1Claims(token, kv)
		return err
	}},
}

// signClaimsWith signs an id1 claim set with an explicit method, key, issuer
// and audience, so a test builds exactly the token under examination.
func signClaimsWith(t *testing.T, method jwt.SigningMethod, key *rsa.PrivateKey, kid, issuer string, audience []string) string {
	t.Helper()
	claims := id1TokenClaims{
		BootID:   "x",
		AuthTime: jwt.NewNumericDate(time.Now()),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   "0000-0001-2345-6789",
			Audience:  jwt.ClaimStrings(audience),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	token := jwt.NewWithClaims(method, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	require.NoError(t, err)
	return signed
}

func TestRS256ValidatorsCheckAudienceAndIssuer(t *testing.T) {
	for _, v := range rs256Validators {
		t.Run(v.name, func(t *testing.T) {
			kv := setupTestKVStore(t)
			kid, priv, err := GetOrCreateSigningKey(kv)
			require.NoError(t, err)

			good := signClaimsWith(t, jwt.SigningMethodRS256, priv, kid, jwtIssuer(), []string{jwtAudience()})
			require.NoError(t, v.validate(good, kv), "a token with this instance's issuer and audience must validate")

			cases := []struct {
				name     string
				issuer   string
				audience []string
			}{
				{"wrong audience", jwtIssuer(), []string{"some-other-audience"}},
				{"no audience", jwtIssuer(), nil},
				{"wrong issuer", "https://some-other-issuer.example", []string{jwtAudience()}},
				{"no issuer", "", []string{jwtAudience()}},
			}
			for _, c := range cases {
				token := signClaimsWith(t, jwt.SigningMethodRS256, priv, kid, c.issuer, c.audience)
				require.Error(t, v.validate(token, kv), "%s must be refused", c.name)
			}
		})
	}
}

func TestRS256ValidatorsPinTheAlgorithmToRS256(t *testing.T) {
	for _, v := range rs256Validators {
		t.Run(v.name, func(t *testing.T) {
			kv := setupTestKVStore(t)
			kid, priv, err := GetOrCreateSigningKey(kv)
			require.NoError(t, err)

			control := signClaimsWith(t, jwt.SigningMethodRS256, priv, kid, jwtIssuer(), []string{jwtAudience()})
			require.NoError(t, v.validate(control, kv), "RS256 control token must validate")

			for _, method := range []jwt.SigningMethod{jwt.SigningMethodRS384, jwt.SigningMethodRS512} {
				token := signClaimsWith(t, method, priv, kid, jwtIssuer(), []string{jwtAudience()})
				require.Error(t, v.validate(token, kv), "%s must be refused", method.Alg())
			}
		})
	}
}

func TestRS256ValidatorsAcceptThePreviousKeyDuringRotationOverlap(t *testing.T) {
	for _, v := range rs256Validators {
		t.Run(v.name, func(t *testing.T) {
			t.Setenv("ID1_JWT_PRIVATE_KEY", "")
			kv := setupTestKVStore(t)
			oldKid, oldPriv, err := GetOrCreateSigningKey(kv)
			require.NoError(t, err)
			signedByOld := signClaimsWith(t, jwt.SigningMethodRS256, oldPriv, oldKid, jwtIssuer(), []string{jwtAudience()})

			require.NoError(t, rotateSigningKey(kv))
			// rotateSigningKey writes the new key to the KV store only. Clearing the
			// in-memory copy of the old key makes resolution read the rotated KV
			// state, as a freshly restarted process does.
			_memKeyMu.Lock()
			_memKeyID = ""
			_memPrivKey = nil
			_memKeyMu.Unlock()

			require.NoError(t, v.validate(signedByOld, kv), "a token signed before the rotation must still validate while the previous key is published")

			newKid, newPriv, err := GetOrCreateSigningKey(kv)
			require.NoError(t, err)
			require.NotEqual(t, oldKid, newKid, "rotation must have produced a new current key")
			signedByNew := signClaimsWith(t, jwt.SigningMethodRS256, newPriv, newKid, jwtIssuer(), []string{jwtAudience()})
			require.NoError(t, v.validate(signedByNew, kv), "a token signed by the new current key must validate")

			stranger, err := rsa.GenerateKey(rand.Reader, 2048)
			require.NoError(t, err)
			signedByStranger := signClaimsWith(t, jwt.SigningMethodRS256, stranger, "stranger", jwtIssuer(), []string{jwtAudience()})
			require.Error(t, v.validate(signedByStranger, kv), "a key id1 never published must stay refused")
		})
	}
}
