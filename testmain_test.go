// apps/backend/containers/id1/testmain_test.go
//
// group: utils
// tags: testing, setup, fixtures
// summary: Test setup and shared fixtures for integration tests.
// Provides test utilities and common initialization logic.
//
//

package id1

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMain loads .env.test from the monorepo root before running tests.
// Go's test runner does not load .env files automatically, so tests that
// read environment variables (e.g. HTTP_FRONTEND_PORT) need this bootstrap.
func TestMain(m *testing.M) {
	loadEnvTest()
	os.Exit(m.Run())
}

// loadEnvTest walks up from the current directory to find .env.test and
// sets any variables that are not already in the environment. This means
// explicit env overrides (e.g. ENV=test go test) still take precedence.
func loadEnvTest() {
	dir, err := os.Getwd()
	if err != nil {
		return
	}
	for {
		path := filepath.Join(dir, ".env.test")
		if _, err := os.Stat(path); err == nil {
			parseEnvFile(path)
			return
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return // reached filesystem root
		}
		dir = parent
	}
}

// parseEnvFile reads a .env file and sets variables that are not already
// present in the environment. Handles KEY=VALUE, quoted values, comments,
// and blank lines.
func parseEnvFile(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		// Strip surrounding quotes
		if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') ||
			(value[0] == '\'' && value[len(value)-1] == '\'')) {
			value = value[1 : len(value)-1]
		}
		// Only set if not already present — explicit env overrides take precedence
		if _, exists := os.LookupEnv(key); !exists {
			os.Setenv(key, value)
		}
	}
}
