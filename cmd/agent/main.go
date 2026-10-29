// Command agent programs pod network namespaces on its node.
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
		fmt.Println("ratatoskr-agent", version.String())
		return
	}
	fmt.Fprintln(os.Stderr, "ratatoskr-agent: not implemented yet")
	os.Exit(1)
}
