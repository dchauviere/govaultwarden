package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/dchauviere/govaultwarden/vaultwarden"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cfg, err := vaultwarden.LoadConfigFromEnv()
	if err != nil {
		fmt.Fprintf(os.Stderr, "configuration error: %v\n", err)
		os.Exit(1)
	}

	client, err := vaultwarden.NewClient(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "client error: %v\n", err)
		os.Exit(1)
	}

	if err := client.Authenticate(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "authentication error: %v\n", err)
		os.Exit(1)
	}

	if len(os.Args) > 1 {
		var response any
		if err := client.Get(ctx, os.Args[1], &response); err != nil {
			fmt.Fprintf(os.Stderr, "request error: %v\n", err)
			os.Exit(1)
		}
		printJSON(response)
		return
	}

	secrets, err := client.ListDecryptedSecrets(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "list decrypted secrets error: %v\n", err)
		os.Exit(1)
	}
	printJSON(secrets)
}

func printJSON(v any) {
	output, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "encode output error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(output))
}
