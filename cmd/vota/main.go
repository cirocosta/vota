package main

import (
	"fmt"
	"os"

	"github.com/cirocosta/vota/internal/cli/root"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	cmd := root.New(root.BuildInfo{
		Version: version,
		Commit:  commit,
		Date:    date,
	})
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
