// Command gateway terminates GENEVE and forwards client traffic into the upstream tunnel.
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
		fmt.Println("ratatoskr-gateway", version.String())
		return
	}
	fmt.Fprintln(os.Stderr, "ratatoskr-gateway: not implemented yet")
	os.Exit(1)
}
