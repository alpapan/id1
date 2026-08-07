// No file in the id1 submodule carries a real credential literal.
//
// A secret committed to a tracked file is disclosed to everyone who can read
// the repository and to every clone and mirror of it, and no later edit takes
// that back: the value stays in history. Fixtures need a credential only to
// prove the code reads one, so the value itself is never load-bearing. Test
// values use the all-zero placeholder, which belongs to nobody and cannot
// authenticate anywhere.
//
// Two independent rules decide a line. The first judges a secret-shaped literal
// assigned to a name that reads as a credential; the second judges a token
// whose own shape identifies its issuer, which is a credential whatever it is
// called. Both are narrower than a general entropy test on purpose: a guard
// that cries wolf gets an exclusion added to it and then guards nothing.
//
// Scope is the whole submodule minus vendor directories, not a hand-listed set
// of roots. A listed root that is renamed or never existed silently narrows the
// scan to nothing and the guard then passes by reaching no files.

package id1

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const credGuardPlaceholder = "00000000-0000-0000-0000-000000000000"

// The seeded secret manifest carries one unfilled placeholder per key, and
// resolve_secret treats a stored value beginning with this prefix as unset and
// mints a fresh secret over it, so such a value never reaches a pod and
// authenticates nowhere. A placeholder that spells out the width it wants passes
// 40 characters while mixing classes, which is the written-out phrase the shape
// rule is documented not to judge. The prefix is what that code tests, so it is
// what this admits: a value carrying the word anywhere later is replaced by
// nothing and stays judged.
const credGuardBootstrapPlaceholderPrefix = "CHANGE_ME"

const credGuardPEMMinimumMaterial = 200

const credGuardMaxNestedAssignments = 4

// A name reads as a credential when one of these words appears anywhere in it,
// so ORCID_CLIENT_SECRET, clientSecret and orcid-client-secret are one case.
// Comparison is on the lowercased name: YAML and JSON keys are conventionally
// lowercase, and a case-sensitive check passes over every one of them.
var credGuardWords = []string{
	"secret", "token", "password", "passwd", "credential",
	"apikey", "api_key", "api-key",
	"privatekey", "private_key", "private-key",
	"accesskey", "access_key", "access-key",
	"authorization", "authorisation",
}

// Words too short or too common to be substrings. They count only as a whole
// name, so `pw` is judged and `PRIMARY_KEY` and `AUTHOR` are not.
var credGuardBareNames = map[string]bool{
	"pw": true, "pwd": true, "pass": true, "key": true, "auth": true,
}

var (
	// Name and value are each captured from a positive class - the characters
	// an identifier and a generated secret are actually written in. Anything
	// that is in neither class, nor a separator, nor whitespace, is decoration
	// and is matched without being captured, so quoting, markdown emphasis,
	// inline code, an HTML tag or sentence punctuation never enters the value
	// and never breaks the anchored shape rules below. Capturing by exclusion
	// instead - a denylist of terminator characters - is what let a value
	// wrapped in backticks pass.
	credGuardDecoration = `[^A-Za-z0-9_.+/=:\s-]*`
	credGuardAssignment = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_.-]*)` + credGuardDecoration +
		`\s*(?::=|[:=])\s*` + credGuardDecoration + `([A-Za-z0-9+/=._-]*[A-Za-z0-9+/=_-])`)

	// A value carrying a separator may hold an assignment of its own, as
	// `--from-literal=NAME=VALUE` does. Matches are non-overlapping in every
	// regex engine these guards are written in, so the outer pair swallows the
	// inner one and the scan resumes past both; each captured value is
	// therefore scanned again.
	credGuardSeparatorInside = regexp.MustCompile(`[:=]`)

	credGuardUUID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	credGuardHex  = regexp.MustCompile(`^[0-9a-fA-F]{32,}$`)

	// A long unbroken base64 run is how a randomly generated key of 32 bytes or
	// more is written down. Length alone is not the test: a written-out English
	// placeholder reaches 60 characters just as easily, and judging it would
	// make the guard cry wolf. Generated material also mixes character classes,
	// and a phrase a human typed does not, so both conditions must hold.
	// The alphabet covers URL-safe base64 (`-` and `_`) as well as standard,
	// because the URL-safe form is what this stack actually mints:
	// `secrets.token_urlsafe(32)` for every callback HMAC and personal access
	// token, and `Fernet.generate_key()` for every encryption key. Restricting
	// the class to `+/` did not merely miss a variant spelling - it admitted
	// those values whenever their random bytes encoded a `-` or `_`, which at
	// 43 characters is nearly every one of them.
	credGuardBase64 = regexp.MustCompile(`^[A-Za-z0-9+/_-]{40,}={0,2}$`)
	credGuardLower  = regexp.MustCompile(`[a-z]`)
	credGuardUpper  = regexp.MustCompile(`[A-Z]`)
	credGuardDigit  = regexp.MustCompile(`[0-9]`)

	credGuardJWT = regexp.MustCompile(`^eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$`)

	// Issuer-prefixed tokens. The prefix is assigned by the issuing service, so
	// a value carrying one is a real credential regardless of the name it is
	// bound to and regardless of whether it is bound to a name at all. Each
	// branch requires the token body length: without it, prose that merely
	// names a prefix is reported, and every document discussing this guard
	// becomes a failure.
	credGuardProviderBody = `gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}` +
		`|sk-proj-[A-Za-z0-9_-]{32,}|sk-[A-Za-z0-9]{32,}|sk_live_[A-Za-z0-9]{16,}|rk_live_[A-Za-z0-9]{16,}` +
		`|GOCSPX-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|ya29\.[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{35}` +
		`|glpat-[A-Za-z0-9_-]{16,}|npm_[A-Za-z0-9]{30,}|dop_v1_[a-f0-9]{40,}|shpat_[a-f0-9]{32}`
	credGuardProvider         = regexp.MustCompile(`(?:` + credGuardProviderBody + `)`)
	credGuardProviderAnchored = regexp.MustCompile(`^(?:` + credGuardProviderBody + `)`)

	// A PEM private key block whose body carries real key material. A
	// placeholder block is admitted by the body length: a fixture writes a word
	// where a key writes hundreds of base64 characters. The body is read across
	// escaped newlines as well as real ones, because a single-line string is
	// how a key most often reaches a fixture.
	credGuardPEM         = regexp.MustCompile(`(?s)-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----(.*?)-----END`)
	credGuardPEMMaterial = regexp.MustCompile(`[A-Za-z0-9+/]+`)
)

var credGuardExcludedDirs = map[string]bool{
	".git": true, ".pixi": true, ".venv": true, ".worktrees": true, ".yarn": true,
	"node_modules": true, "vendor": true, "dist": true, "build": true,
}

// Gitignored files legitimately hold live credentials. The guard never opens
// one: reading it to judge it would copy the value into a test process and into
// any failure output. In this submodule .env.test is a symlink to the
// repository root's, which makes never opening it the whole point. They are
// excluded by name as well as by suffix so that a widened suffix set cannot
// reach them by accident.
var credGuardNeverOpened = map[string]bool{
	".env": true, ".env.test": true, ".env.production": true,
	".env.local": true, ".env.dev": true,
}

// Language-agnostic on purpose. A guard scoped to the languages a repository
// happens to contain today goes blind the moment a stray script of another
// kind lands in it, and says nothing while it does.
var credGuardSuffixes = map[string]bool{
	".py":       true,
	".ts":       true,
	".tsx":      true,
	".js":       true,
	".jsx":      true,
	".mjs":      true,
	".cjs":      true,
	".go":       true,
	".json":     true,
	".yaml":     true,
	".yml":      true,
	".toml":     true,
	".template": true,
	".sh":       true,
	".md":       true,
	".example":  true,
	".cfg":      true,
	".ini":      true,
	".rest":     true,
	// `main.go_` is deployed source: the Dockerfile copies it to cmd/main.go and
	// builds it. The underscore suffix keeps it out of this module, so
	// `go test ./...` never compiles it and no other test in this repository can
	// see it - which leaves this guard as its only net. It carries config and
	// environment handling, so it is exactly where a credential lands.
	".go_": true,
}

func credGuardIsCredentialName(name string) bool {
	lowered := strings.ToLower(name)
	if credGuardBareNames[lowered] {
		return true
	}
	for _, word := range credGuardWords {
		if strings.Contains(lowered, word) {
			return true
		}
	}
	return false
}

func credGuardLooksGenerated(value string) bool {
	return credGuardLower.MatchString(value) &&
		credGuardUpper.MatchString(value) &&
		credGuardDigit.MatchString(value)
}

func credGuardIsSecretShaped(value string) bool {
	if value == credGuardPlaceholder ||
		strings.HasPrefix(value, credGuardBootstrapPlaceholderPrefix) {
		return false
	}
	if credGuardUUID.MatchString(value) || credGuardHex.MatchString(value) {
		return true
	}
	if credGuardBase64.MatchString(value) && credGuardLooksGenerated(value) {
		return true
	}
	return credGuardProviderAnchored.MatchString(value) || credGuardJWT.MatchString(value)
}

// credGuardLineOffends reports whether one line carries a credential, by either
// of the two rules.
func credGuardLineOffends(line string) bool {
	if credGuardProvider.MatchString(line) {
		return true
	}
	// Every rescan is over a strictly shorter string, and the depth is bounded
	// so a pathological line cannot drive the scan indefinitely.
	texts := []string{line}
	for depth := 0; depth < credGuardMaxNestedAssignments; depth++ {
		var nested []string
		for _, text := range texts {
			for _, match := range credGuardAssignment.FindAllStringSubmatch(text, -1) {
				if credGuardIsCredentialName(match[1]) && credGuardIsSecretShaped(match[2]) {
					return true
				}
				if credGuardSeparatorInside.MatchString(match[2]) {
					nested = append(nested, match[2])
				}
			}
		}
		if len(nested) == 0 {
			return false
		}
		texts = nested
	}
	return false
}

// credGuardTextOffendsWithPEM reports whether a file's whole text carries a PEM
// private key with real material.
func credGuardTextOffendsWithPEM(text string) bool {
	for _, match := range credGuardPEM.FindAllStringSubmatch(text, -1) {
		material := 0
		for _, run := range credGuardPEMMaterial.FindAllString(match[1], -1) {
			material += len(run)
		}
		// Total base64 content, not the longest run: a real key is wrapped at 64
		// columns, so run length says nothing about it. An RSA-2048 body is about
		// 1600 characters and the smallest useful EC key about 200, while a
		// truncated fixture is a few dozen.
		if material >= credGuardPEMMinimumMaterial {
			return true
		}
	}
	return false
}

// credGuardRepoRoot walks upward for go.mod so the scan is anchored to the
// submodule rather than to whatever directory the runner happened to start in.
func credGuardRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod found above the working directory")
		}
		dir = parent
	}
}

// credGuardScannedFiles lists every file this guard judges, excluding the guard
// itself. This file quotes credential-shaped literals so the rules can be shown
// positive cases, and a rule that cannot be shown one is untested. Judging
// itself would therefore report itself.
func credGuardScannedFiles(t *testing.T, root string) []string {
	t.Helper()
	var found []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			// Pruned during the walk, not filtered after it: a vendor directory
			// holds more files than the repository does, and descending into
			// one costs more than every judgement this guard makes.
			if path != root && credGuardExcludedDirs[entry.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		name := entry.Name()
		if !credGuardSuffixes[filepath.Ext(name)] || credGuardNeverOpened[name] {
			return nil
		}
		if name == "no_real_credentials_test.go" {
			return nil
		}
		found = append(found, path)
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	return found
}

func TestNoTrackedFileCarriesARealCredentialLiteral(t *testing.T) {
	root := credGuardRepoRoot(t)
	var offenders []string
	for _, path := range credGuardScannedFiles(t, root) {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		text := string(raw)
		relative, _ := filepath.Rel(root, path)
		for index, line := range strings.Split(text, "\n") {
			if credGuardLineOffends(line) {
				offenders = append(offenders, relative+":"+strconv.Itoa(index+1))
			}
		}
		if credGuardTextOffendsWithPEM(text) {
			offenders = append(offenders, relative+": PEM private key with real material")
		}
	}
	if len(offenders) > 0 {
		// Offending lines are named without their values, deliberately.
		t.Fatalf("%d credential-shaped literal(s) in tracked files. Use %s; a real value belongs in .env.test, which is not tracked:\n%s",
			len(offenders), credGuardPlaceholder, strings.Join(offenders, "\n"))
	}
}

// TestCredGuardScanReachesThisSubmodulesFiles is the canary. A suffix or scope
// error would empty the file list and pass vacuously.
func TestCredGuardScanReachesThisSubmodulesFiles(t *testing.T) {
	root := credGuardRepoRoot(t)
	scanned := credGuardScannedFiles(t, root)
	if len(scanned) < 40 {
		t.Fatalf("scan reached only %d files, which is too few to be the whole submodule", len(scanned))
	}
	// Coverage is not Go-only. Narrowing to one language is the way a scan goes
	// blind while still reporting a large count.
	suffixes := map[string]bool{}
	sawAuthGo := false
	for _, path := range scanned {
		suffixes[filepath.Ext(path)] = true
		if filepath.Base(path) == "auth.go" {
			sawAuthGo = true
		}
	}
	if !sawAuthGo {
		t.Fatal("scan never reached auth.go")
	}
	for _, needed := range []string{".go", ".md"} {
		if !suffixes[needed] {
			t.Fatalf("scan reached no %s file", needed)
		}
	}
}

// TestCredGuardNeverOpensAGitignoredEnvFile: those files legitimately hold live
// credentials and must not be read.
func TestCredGuardNeverOpensAGitignoredEnvFile(t *testing.T) {
	root := credGuardRepoRoot(t)
	for _, path := range credGuardScannedFiles(t, root) {
		if credGuardNeverOpened[filepath.Base(path)] {
			t.Fatalf("scan would open %s", path)
		}
	}
}

// TestCredGuardAdmittedAndRejectedSampleLines pins both directions together.
// Without the rejected cases this guard could pass by matching nothing at all,
// which is exactly how the disclosure it exists to stop went unnoticed. Every
// admitted case must be admitted for a stated reason, not because the pattern
// never looked at it.
func TestCredGuardAdmittedAndRejectedSampleLines(t *testing.T) {
	const real = "ff62a1de-4f1c-4d2b-9f7e-2b8c1a0d5e33"
	admitted := []string{
		`ORCID_CLIENT_SECRET="` + credGuardPlaceholder + `"`,
		`        orcid-client-secret: ` + credGuardPlaceholder,
		`{"ORCID_CLIENT_SECRET": "` + credGuardPlaceholder + `"}`,
		`ORCID_CLIENT_ID="a-client-id-is-not-a-credential"`,
		`assemblyUUID := "` + real + `"`,
		`PRIMARY_KEY = "` + real + `"`,
		`AUTHOR = "` + real + `"`,
		// An issuer prefix named in prose is not a token. Requiring the body
		// length is what separates the two.
		`prose naming the ghp_ prefix, or AKIA, carries no token`,
		// Decoration is tolerated around a name and a value, not treated as
		// part of either, so a name that merely reads as a credential in prose
		// still forms no pair and a path-shaped value is still no secret.
		`we set the ORCID_CLIENT_SECRET in the env file`,
		`token: docs/plans/reviews/a-review-r1.md`,
		// An unfilled bootstrap placeholder. resolve_secret treats any value
		// beginning CHANGE_ME as unset and mints a fresh secret over it, so such
		// a value never reaches a pod and authenticates nowhere. The seeded
		// manifest writes one per key, and a placeholder spelling out the width
		// it wants passes 40 characters while mixing classes, which is the
		// written-out phrase the shape rule is documented not to judge.
		`CURATORIUM_JWT_SECRET: "CHANGE_ME_replace_with_a_64_byte_hex_signing_secret"`,
	}
	for _, line := range admitted {
		if credGuardLineOffends(line) {
			t.Errorf("admitted line was reported: %s", line)
		}
	}

	rejected := []string{
		`ORCID_CLIENT_SECRET="` + real + `"`,
		`ORCID_CLIENT_SECRET: ` + real,
		`        orcid-client-secret: ` + real,
		`nextcloud_app_password: ` + real,
		`clientSecret := "` + real + `"`,
		`pw = "` + real + `"`,
		`{"NEXTCLOUD_APP_PASSWORD": "` + real + `"}`,
		`export SLURM_CALLBACK_TOKEN=` + real,
		`API_KEY = "` + real + `"`,
		`SECRET = "a3f9c2e81b7d45069af3c2e8b1d7405963fa2c1e"`,
		`API_TOKEN = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"`,
		`API_KEY = "AKIAIOSFODNN7EXAMPLE"`,
		`TOKEN = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.aBcDeFgHiJkLmNoPqRsTuVwXyZ01234"`,
		// URL-safe base64, 43 characters carrying both `-` and `_`: the shape of
		// `secrets.token_urlsafe(32)`, and of a Fernet key with its trailing pad.
		// Synthetic - authenticates nowhere.
		`SLURM_CALLBACK_TOKEN = "aB3dEf5GhI7jKl9MnO1pQr3StU5vWx7YzA9bCd-Ef_h"`,
		`USER_CREDENTIALS_ENCRYPTION_KEY = "aB3dEf5GhI7jKl9MnO1pQr3StU5vWx7YzA9bCd-Ef_h="`,
		`aBareNameButAnIssuerPrefixedToken = ghp_16C7e42F292c6912E7710c838347Ae178B4a`,
		// Decoration around the name or the value. A guard whose value class is
		// a denylist of terminators captures the decoration too, fails its own
		// anchored shape test, and reports the line clean - which is how two
		// real values sat in tracked markdown while this guard passed.
		"`ORCID_CLIENT_SECRET=" + real + "`",
		`The value was ORCID_CLIENT_SECRET=` + real + `.`,
		"**ORCID_CLIENT_SECRET**: `" + real + "`",
		`~~ORCID_CLIENT_SECRET~~=` + real,
		`<code>ORCID_CLIENT_SECRET=` + real + `</code>`,
		`ORCID_CLIENT_SECRET=` + real + `!`,
		`was ORCID_CLIENT_SECRET=` + real + `?`,
		"ORCID_CLIENT_SECRET=\u201c" + real + "\u201d",
		`{orcid_client_secret: ` + real + `}`,
		// An assignment nested inside the value of an outer one. A
		// non-overlapping scan binds the outer pair and steps over the inner.
		`kubectl create secret generic x --from-literal=orcid-client-secret=` + real,
		`--opt=--from-literal=orcid-client-secret=` + real,
		// The bootstrap placeholder is admitted by its PREFIX, matching what
		// resolve_secret tests. A value merely carrying the word later on is
		// replaced by nothing and is still a credential.
		`SECRET = "not_CHANGE_ME_aB3dEf5GhI7jKl9MnO1pQr3StU5vWx7YzA9bCd-Ef_h"`,
		// Case-sensitively, as resolve_secret tests it. A lowercased spelling is
		// not the placeholder that code replaces, so a value wearing it is live
		// and stays judged.
		`SECRET = "change_me_aB3dEf5GhI7jKl9MnO1pQr3StU5vWx7YzA9bCd-Ef_h"`,
	}
	for _, line := range rejected {
		if !credGuardLineOffends(line) {
			t.Errorf("rejected line was admitted: %s", line)
		}
	}
}

func TestCredGuardPlaceholderPEMAdmittedAndRealMaterialRejected(t *testing.T) {
	placeholder := "-----BEGIN PRIVATE KEY-----\nunit-test\n-----END PRIVATE KEY-----\n"
	if credGuardTextOffendsWithPEM(placeholder) {
		t.Error("a placeholder PEM was reported")
	}
	material := strings.Repeat("MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDe", 8)
	real := "-----BEGIN RSA PRIVATE KEY-----\n" + material + "\n-----END RSA PRIVATE KEY-----\n"
	if !credGuardTextOffendsWithPEM(real) {
		t.Error("a PEM with real material was admitted")
	}
	if !credGuardTextOffendsWithPEM(strings.ReplaceAll(real, "\n", `\n`)) {
		t.Error("a single-line PEM with real material was admitted")
	}
	// A real key is wrapped at 64 columns, so no single run reaches the
	// threshold; only the total does.
	var wrapped strings.Builder
	for index := 0; index < len(material); index += 64 {
		end := index + 64
		if end > len(material) {
			end = len(material)
		}
		wrapped.WriteString(material[index:end] + "\n")
	}
	if !credGuardTextOffendsWithPEM("-----BEGIN PRIVATE KEY-----\n" + wrapped.String() + "-----END PRIVATE KEY-----\n") {
		t.Error("a column-wrapped PEM with real material was admitted")
	}
}
