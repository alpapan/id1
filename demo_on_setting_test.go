//go:build curatoriumdemo

package id1

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// unusableDemoUserValues are the values of ORCID_DEMO_USER the demo mint treats as unset:
// empty, and anything that is not an ORCID iD.
var unusableDemoUserValues = []string{"", "not-an-orcid"}

func TestUnusableDemoUserValues_CaseList(t *testing.T) {
	assert.ElementsMatch(t, []string{"", "not-an-orcid"}, unusableDemoUserValues)
}

func TestRegisterDemoRoutes_HaltsWhenDemoUserSettingIsUnusable(t *testing.T) {
	for _, value := range unusableDemoUserValues {
		t.Run("value="+value, func(t *testing.T) {
			t.Setenv("ORCID_DEMO_USER", value)
			assert.Panics(t, func() {
				RegisterDemoRoutes(http.NewServeMux(), ID1KeyValueStore{})
			})
		})
	}
}

func TestHandleDemoUser_RefusesWhenDemoUserSettingIsUnusable(t *testing.T) {
	kv := setupTestKVStore(t)
	for _, value := range unusableDemoUserValues {
		t.Run("value="+value, func(t *testing.T) {
			t.Setenv("ORCID_DEMO_USER", value)
			rec := httptest.NewRecorder()
			HandleDemoUser(kv)(rec, httptest.NewRequest(http.MethodGet, "/auth/unauth_demo", nil))
			assert.Equal(t, http.StatusInternalServerError, rec.Code)
			assert.NotContains(t, rec.Body.String(), "jwt")
		})
	}
}
