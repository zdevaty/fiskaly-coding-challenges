package main

import (
	"log"

	"github.com/zdevaty/fiskaly-coding-challenges/signing-service-challenge/api"
	"github.com/zdevaty/fiskaly-coding-challenges/signing-service-challenge/persistence"
)

const (
	ListenAddress = ":8081"
	// TODO: add further configuration parameters here ...
)

func main() {
	store := persistence.NewInMemoryDeviceStore()
	server := api.NewServer(ListenAddress, store)

	if err := server.Run(); err != nil {
		log.Fatal("Could not start server on ", ListenAddress)
	}
}
