// Command rabbit runs bunny.net's BunnyCLI through Nordray White Rabbit, so the real bunny.net API key never
// leaves the server. See `rabbit --help`.
package main

import (
	"context"
	"os"

	"github.com/activout/nordray.whiterabbit/cli/internal/app"
)

func main() {
	os.Exit(app.New().Run(context.Background(), os.Args[1:]))
}
