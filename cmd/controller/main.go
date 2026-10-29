// Command controller reconciles EgressGateway and EgressPolicy objects.
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
		fmt.Println("ratatoskr-controller", version.String())
		return
	}
	fmt.Fprintln(os.Stderr, "ratatoskr-controller: not implemented yet")
	os.Exit(1)
}
