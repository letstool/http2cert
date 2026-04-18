// Command certinfo parses an X.509 certificate (PEM or DER) and prints all
// information as indented JSON - equivalent to `openssl x509 -noout -text`.
//
// Usage:
//
//	certinfo [flags] [file]
//
// Flags:
//
//	-in  <file>     certificate file (default: stdin)
//	-out <file>     output file (default: stdout)
//	-compact        compact JSON instead of indented
//	-chain          parse all certificates in a PEM chain
//
// Examples:
//
//	certinfo -in cert.pem
//	certinfo cert.der
//	openssl s_client -connect example.com:443 </dev/null 2>/dev/null | certinfo
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/you/certinfo/pkg/certinfo"
)

func main() {
	inFile := flag.String("in", "", "input certificate file (PEM or DER); defaults to stdin")
	outFile := flag.String("out", "", "output file; defaults to stdout")
	compact := flag.Bool("compact", false, "compact JSON (no indentation)")
	chain := flag.Bool("chain", false, "parse all PEM blocks in a chain")
	flag.Parse()

	// Also accept a positional argument as the input file
	if *inFile == "" && flag.NArg() > 0 {
		*inFile = flag.Arg(0)
	}

	// -- Input ----------------------------------------------------------------
	var data []byte
	var err error

	if *inFile == "" || *inFile == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(*inFile)
	}
	must(err, "read input")

	// -- Output ---------------------------------------------------------------
	out := os.Stdout
	if *outFile != "" && *outFile != "-" {
		f, ferr := os.Create(*outFile)
		must(ferr, "create output file")
		defer f.Close()
		out = f
	}

	// -- Parse ----------------------------------------------------------------
	enc := json.NewEncoder(out)
	if !*compact {
		enc.SetIndent("", "  ")
	}

	if *chain {
		certs, perr := certinfo.ParseChain(data)
		must(perr, "parse certificate chain")
		must(enc.Encode(certs), "encode JSON")
		return
	}

	info, perr := certinfo.Parse(data)
	must(perr, "parse certificate")
	must(enc.Encode(info), "encode JSON")
}

func must(err error, ctx string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "certinfo: %s: %v\n", ctx, err)
		os.Exit(1)
	}
}
