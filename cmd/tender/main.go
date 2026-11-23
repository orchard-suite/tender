// Command tender is the suite's device agent.
package main

import (
	"os"

	"github.com/orchard-suite/tender/internal/cli"
)

func main() { os.Exit(cli.Main(os.Args[1:])) }
