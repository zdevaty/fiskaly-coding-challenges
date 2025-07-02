package main

import (
	"log"

	"github.com/zdevaty/fiskaly-coding-challenges/signing-service-challenge/api"
)

const (
	ListenAddress = ":8081"
	// TODO: add further configuration parameters here ...
)

func main() {
	server := api.NewServer(ListenAddress)

	if err := server.Run(); err != nil {
		log.Fatal("Could not start server on ", ListenAddress)
	}
}
