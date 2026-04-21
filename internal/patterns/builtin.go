package patterns

// builtinRaw defines the default pattern set shipped with secretscanner.
// Compiled once at program init; a failure here is a bug in the pattern
// definition, not a runtime error — hence the panic.
var builtinRaw = []RawPattern{
	{
		Name:        "aws-access-key",
		Description: "AWS access key ID",
		Regex:       `AKIA[0-9A-Z]{16}`,
		Severity:    "critical",
	},
	{
		Name:        "aws-secret-key",
		Description: "AWS secret access key",
		Regex:       `(?i)aws[_\-]?secret[_\-]?(?:access[_\-]?)?key\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}`,
		Severity:    "critical",
	},
	{
		Name:        "github-pat",
		Description: "GitHub personal access token",
		Regex:       `ghp_[A-Za-z0-9]{36}`,
		Severity:    "critical",
	},
	{
		Name:        "github-oauth",
		Description: "GitHub OAuth token",
		Regex:       `gho_[A-Za-z0-9]{36}`,
		Severity:    "critical",
	},
	{
		Name:        "stripe-live-secret",
		Description: "Stripe live secret key",
		Regex:       `sk_live_[A-Za-z0-9]{24,}`,
		Severity:    "critical",
	},
	{
		Name:        "stripe-live-publishable",
		Description: "Stripe live publishable key",
		Regex:       `pk_live_[A-Za-z0-9]{24,}`,
		Severity:    "high",
	},
	{
		Name:        "generic-api-key",
		Description: "Generic API key",
		Regex:       `(?i)api[_-]?key\s*[:=]\s*["']?[A-Za-z0-9]{20,}`,
		Severity:    "high",
	},
	{
		Name:        "generic-secret",
		Description: "Generic secret value",
		Regex:       `(?i)secret\s*[:=]\s*["'][^"']{8,}`,
		Severity:    "high",
	},
	{
		Name:        "generic-password",
		Description: "Generic password value",
		Regex:       `(?i)password\s*[:=]\s*["'][^"']{8,}`,
		Severity:    "high",
	},
	{
		Name:        "private-key-pem",
		Description: "PEM-encoded private key",
		Regex:       `-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----`,
		Severity:    "critical",
	},
	{
		Name:        "jwt",
		Description: "JSON Web Token (JWT)",
		Regex:       `eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`,
		Severity:    "medium",
	},
	{
		Name:        "slack-token",
		Description: "Slack API token",
		Regex:       `xox[baprs]-[A-Za-z0-9-]+`,
		Severity:    "high",
	},
	{
		Name:        "connection-string",
		Description: "Database connection string with credentials",
		Regex:       `(?i)(mongodb|postgresql|mysql|redis)://[^:]+:[^@]+@`,
		Severity:    "high",
	},
	{
		Name:        "sendgrid-api-key",
		Description: "SendGrid API key",
		Regex:       `SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}`,
		Severity:    "critical",
	},
	{
		Name:        "twilio-account-sid",
		Description: "Twilio account SID",
		Regex:       `AC[a-z0-9]{32}`,
		Severity:    "high",
	},
}

var compiledBuiltins []Pattern

func init() {
	compiledBuiltins = make([]Pattern, 0, len(builtinRaw))
	for _, raw := range builtinRaw {
		p, err := Compile(raw)
		if err != nil {
			panic("secretscanner: invalid built-in pattern: " + err.Error())
		}
		compiledBuiltins = append(compiledBuiltins, p)
	}
}

// BuiltinPatterns returns the compiled default pattern set.
// The returned slice must not be modified by the caller.
func BuiltinPatterns() []Pattern {
	return compiledBuiltins
}
