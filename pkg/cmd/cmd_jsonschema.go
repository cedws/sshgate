package cmd

import (
	"encoding/json"
	"log"
	"os"

	"github.com/cedws/sshgate/pkg/sshgate"
	"github.com/swaggest/jsonschema-go"
)

type jsonschemaCmd struct{}

func (j *jsonschemaCmd) Run() error {
	reflector := jsonschema.Reflector{}
	schema, err := reflector.Reflect(sshgate.Config{})
	if err != nil {
		log.Fatal(err)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")

	return enc.Encode(schema)
}
