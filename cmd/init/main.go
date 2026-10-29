// Command init programs the pod network namespace from inside the pod (init driver) or waits for the agent (agent driver).
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/skaldhall/ratatoskr/pkg/version"
)

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println("ratatoskr-init", version.String())
		return
	}
	fmt.Fprintln(os.Stderr, "ratatoskr-init: not implemented yet")
	os.Exit(1)
}
