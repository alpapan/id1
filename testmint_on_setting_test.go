//go:build testmint

package id1

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// The demo user sits outside the reserved test range, so the test mint signs for it only
// when ORCID_DEMO_USER names it. An unset setting names no demo user.
func TestIsTestMintOrcid_DemoUserComesFromTheSetting(t *testing.T) {
	const outsideTheRange = "0000-0002-1825-0097" // ORCID's published example, in its issuing block

	t.Setenv("ORCID_DEMO_USER", "")
	assert.False(t, isTestMintOrcid(outsideTheRange), "an unset setting must name no demo user")

	t.Setenv("ORCID_DEMO_USER", outsideTheRange)
	assert.True(t, isTestMintOrcid(outsideTheRange), "the iD the setting names must be signable")

	t.Setenv("ORCID_DEMO_USER", "0000-0001-0000-0009")
	assert.False(t, isTestMintOrcid(outsideTheRange), "an iD the setting does not name must stay refused")
}
