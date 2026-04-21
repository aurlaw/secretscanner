package main

import (
	"fmt"

	"github.com/aurlaw/secretscanner/internal/version"
)

func main() {
	fmt.Printf("secretscanner %s (%s)\n", version.Version, version.Commit)
}
