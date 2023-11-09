package main

import (
	"github.com/bom-squad/go-cli/pkg/format"
	"github.com/bom-squad/protobom/pkg/sbom"
	"github.com/bom-squad/protobom/pkg/writer"
	"google.golang.org/protobuf/proto"
	"io/ioutil"
	"log"
	"os"
)

func main() {

	if len(os.Args) != 2 {
		log.Fatalln("Usage: protobom-writer <output format>")
	}
	fmt, err := format.ParseFormat(os.Args[1], "json")
	if err != nil {
		log.Fatalln("Failed to parse output format:", err)
	}

	input, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		log.Fatalln("Failed to read from stdin:", err)
	}

	document := &sbom.Document{}
	if err := proto.Unmarshal(input, document); err != nil {
		log.Fatalln("Failed to parse protobuf:", err)
	}

	w := writer.New()
	if err := w.WriteStreamWithOptions(
		document, os.Stdout, &writer.Options{Format: fmt.Format},
	); err != nil {
		log.Fatalln("Failed to generate sbom:", err)
	}
}
