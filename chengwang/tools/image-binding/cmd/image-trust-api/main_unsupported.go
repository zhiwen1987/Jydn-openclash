//go:build !linux

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "managed image trust candidate requires native Linux durability")
	os.Exit(1)
}
