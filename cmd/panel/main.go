package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"gravity-dns/internal/config"
	"gravity-dns/internal/panel"
	"gravity-dns/internal/resolver"
	"gravity-dns/internal/store"
)

func main() {
	configPath := flag.String("config", "", "Path to gravity.yaml configuration file")
	flag.Parse()

	log.Println("[PANEL] Starting GravityDNS Web Management Panel...")

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("[PANEL] Configuration error: %v", err)
	}

	st, err := store.New(&cfg.Redis)
	if err != nil {
		log.Fatalf("[PANEL] Redis store connection error: %v", err)
	}
	defer st.Close()

	res, err := resolver.New(cfg, st)
	if err != nil {
		log.Fatalf("[PANEL] Resolver initialization error: %v", err)
	}

	server := panel.NewServer(cfg, st, res, nil)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.Printf("[PANEL] Received signal %v, gracefully shutting down...", sig)
		_ = server.Close()
	}()

	if err := server.Start(); err != nil {
		log.Fatalf("[PANEL] Panel stopped: %v", err)
	}
}
