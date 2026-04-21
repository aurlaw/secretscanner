package version

// Version and Commit are stamped at build time via ldflags:
//
//	-X github.com/aurlaw/secretscanner/internal/version.Version=<tag>
//	-X github.com/aurlaw/secretscanner/internal/version.Commit=<sha>
//
// They fall back to "dev" / "unknown" for local builds without ldflags.
var (
	Version = "dev"
	Commit  = "unknown"
)
