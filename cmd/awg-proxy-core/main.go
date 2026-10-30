package main

import (
	"github.com/mkulkov/awg-local-proxy-core/core"
	"os"
)

func main() {
	if len(os.Args) != 2 || os.Args[1] != "--control-stdio" {
		os.Exit(2)
	}
	if core.Serve(os.Stdin, os.Stdout) != nil {
		os.Exit(1)
	}
}
