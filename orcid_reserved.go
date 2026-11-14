package id1

import (
	"os"
	"strings"
)

// reservedOrcidBlockPrefix opens the block of iDs this deployment keeps for its
// own accounts: the system accounts 0000-0000-0000-0001 to 0000-0000-0000-0009
// (admin, files, provisioner and the rest) and the test identities above them.
// Those identities sign in only through trusted paths (the dev/test mint, the
// internal-secret and mTLS provisioning routes), never through an ORCID login.
const reservedOrcidBlockPrefix = "0000-0000-"

// isReservedOrcidBlock reports whether orcid lies in the reserved block. It is
// deliberately wider than the checksum-valid test range: any iD whose first two
// groups are 0000-0000- is refused, whatever its check character.
func isReservedOrcidBlock(orcid string) bool {
	return strings.HasPrefix(orcid, reservedOrcidBlockPrefix)
}

// isTrustedPathOnlyOrcid reports whether orcid signs in only through trusted paths:
// the reserved block above, or the demo user the ORCID_DEMO_USER setting names (it may
// lie outside the block). An unset setting names no iD. Public device-key enrolment
// refuses these identities whatever amr the presenting token carries.
func isTrustedPathOnlyOrcid(orcid string) bool {
	if isReservedOrcidBlock(orcid) {
		return true
	}
	demoUser := os.Getenv("ORCID_DEMO_USER")
	return demoUser != "" && orcid == demoUser
}
