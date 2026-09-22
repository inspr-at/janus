// Verify the complete offline closure before every supported local/container build.
package main

import (
	"barta.cm/janus/internal/versioninfo"
	"fmt"
	"os"
)

func main() {
	if err := versioninfo.VerifyPresentation(os.DirFS("internal/versioninfo")); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("ok: release coordinate and offline presentation closure")
}
