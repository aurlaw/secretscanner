package patterns_test

import (
	"strings"
	"testing"

	"github.com/aurlaw/secretscanner/internal/patterns"
)

// testFixtures builds credential-shaped strings at runtime rather than
// storing them as literals. This prevents GitHub push protection from
// treating test data as real secrets — an unavoidable tension when the
// project is itself a secret scanner.
var (
	fixtureStripeLiveSecret      = "STRIPE_KEY=sk_" + "live_" + strings.Repeat("a", 24)
	fixtureStripeLivePublishable = "STRIPE_PK=pk_" + "live_" + strings.Repeat("a", 24)
	fixtureStripeTestNoMatch     = "STRIPE_PK=pk_" + "test_" + strings.Repeat("a", 24)
	fixtureSendGridKey           = "SG." + strings.Repeat("a", 22) + "." + strings.Repeat("a", 43)
	fixtureTwilioSID             = "sid: AC" + strings.Repeat("a", 32)
	fixtureTwilioNoMatch         = "sid: AC" + strings.Repeat("a", 4) // too short
)

func findPattern(t *testing.T, name string) patterns.Pattern {
	t.Helper()
	for _, p := range patterns.BuiltinPatterns() {
		if p.Name == name {
			return p
		}
	}
	t.Fatalf("pattern %q not found in built-in set", name)
	return patterns.Pattern{}
}

func TestBuiltinPatterns_Count(t *testing.T) {
	got := len(patterns.BuiltinPatterns())
	if got != 15 {
		t.Errorf("BuiltinPatterns() returned %d patterns, want 15", got)
	}
}

func TestBuiltinPatterns_NoNilRegex(t *testing.T) {
	for _, p := range patterns.BuiltinPatterns() {
		if p.Regex == nil {
			t.Errorf("pattern %q has nil Regex", p.Name)
		}
	}
}

func TestBuiltinPatterns_MatchAndNoMatch(t *testing.T) {
	tests := []struct {
		patternName string
		matchLine   string
		noMatchLine string
	}{
		{
			patternName: "aws-access-key",
			matchLine:   "export KEY=AKIAIOSFODNN7EXAMPLE",
			noMatchLine: "export KEY=AKIASHORT",
		},
		{
			patternName: "aws-secret-key",
			matchLine:   "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			noMatchLine: "aws_secret_access_key = tooshort",
		},
		{
			patternName: "github-pat",
			matchLine:   "token: ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ",
			noMatchLine: "token: ghp_short",
		},
		{
			patternName: "github-oauth",
			matchLine:   "token: gho_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ",
			noMatchLine: "token: gho_x",
		},
		{
			patternName: "stripe-live-secret",
			matchLine:   fixtureStripeLiveSecret,
			noMatchLine: "STRIPE_KEY=sk_" + "test_" + strings.Repeat("a", 24),
		},
		{
			patternName: "stripe-live-publishable",
			matchLine:   fixtureStripeLivePublishable,
			noMatchLine: fixtureStripeTestNoMatch,
		},
		{
			patternName: "generic-api-key",
			matchLine:   `api_key = "abcdefghijklmnopqrstu"`,
			noMatchLine: `api_key = "short"`,
		},
		{
			patternName: "generic-secret",
			matchLine:   `secret = "mysupersecretvalue"`,
			noMatchLine: `secret = "tiny"`,
		},
		{
			patternName: "generic-password",
			matchLine:   `password = "mysecretpassword"`,
			noMatchLine: `password = "short"`,
		},
		{
			patternName: "private-key-pem",
			matchLine:   "-----BEGIN RSA PRIVATE KEY-----",
			noMatchLine: "-----BEGIN CERTIFICATE-----",
		},
		{
			patternName: "jwt",
			matchLine:   "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POkX",
			noMatchLine: "not.a.jwt",
		},
		{
			patternName: "slack-token",
			matchLine:   "token=xoxb-123456789012-1234567890123-abc",
			noMatchLine: "token=xoxz-invalid",
		},
		{
			patternName: "connection-string",
			matchLine:   "mongodb://admin:s3cr3t@localhost:27017",
			noMatchLine: "mongodb://localhost:27017",
		},
		{
			patternName: "sendgrid-api-key",
			matchLine:   fixtureSendGridKey,
			noMatchLine: "SG.short.key",
		},
		{
			patternName: "twilio-account-sid",
			matchLine:   fixtureTwilioSID,
			noMatchLine: fixtureTwilioNoMatch,
		},
	}

	for _, tc := range tests {
		t.Run(tc.patternName, func(t *testing.T) {
			p := findPattern(t, tc.patternName)

			if !p.Regex.MatchString(tc.matchLine) {
				t.Errorf("pattern %q did not match %q", tc.patternName, tc.matchLine)
			}
			if p.Regex.MatchString(tc.noMatchLine) {
				t.Errorf("pattern %q unexpectedly matched %q", tc.patternName, tc.noMatchLine)
			}
		})
	}
}
