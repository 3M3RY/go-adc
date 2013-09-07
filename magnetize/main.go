package main

import (
	"encoding/base32"
	"flag"
	"fmt"
	"github.com/3M3RY/go-hashtree"
	"github.com/3M3RY/go-tiger"
	"io"
	"net/url"
	"os"
	"strings"
)

func main() {
	flag.Parse()
	if len(flag.Args()) == 0 {
		fmt.Println("file not specified")
		os.Exit(1)
	}

	for _, arg := range flag.Args() {

		file, err := os.OpenFile(arg, os.O_RDONLY, 0)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error opening", arg+":", err)
			os.Exit(1)
		}
		info, err := file.Stat()
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error getting file stats:", err)
			os.Exit(1)
		}

		if info.IsDir() {
			fmt.Fprintln(os.Stderr, "Skipping directory", arg)
			continue
		}
		if info.Size() == 0 {
			fmt.Fprintln(os.Stderr, "Skipping empty file", arg)
			continue
		}

		tree := hashtree.New(tiger.New())
		leaf := tiger.New()

		leafChunk := make([]byte, 1025)
		leafChunk[0] = 0
		fileChunk := leafChunk[1:]

		var n int
		for err == nil {
			n, err = file.Read(fileChunk)
			if n > 0 {
				leaf.Write(leafChunk[:n+1])
				tree.Write(leaf.Sum(nil))
				leaf.Reset()
			}
		}

		if err != nil && err != io.EOF {
			fmt.Fprintln(os.Stderr, "Error hashing", info.Name()+",", err)
			continue
		}

		hash := strings.Split(base32.StdEncoding.EncodeToString(tree.Sum(nil)), "=")[0]
		fmt.Fprintf(os.Stdout, "magnet:?dn=%s&xl=%d&xt=urn:tree:tiger:%s\n", url.QueryEscape(info.Name()), info.Size(), hash)
	}
	os.Exit(0)
}
