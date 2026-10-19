package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"gravity-dns/internal/config"
	"gravity-dns/internal/resolver"
	"gravity-dns/internal/sniproxy"
	"gravity-dns/internal/store"
)

func main() {
	configPath := flag.String("config", "", "Path to gravity.yaml configuration file")
	flag.Parse()

	log.Println("[SNI-PROXY] Starting GravityDNS Transparent SNI Router...")

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("[SNI-PROXY] Configuration error: %v", err)
	}

	st, err := store.New(&cfg.Redis)
	if err != nil {
		log.Fatalf("[SNI-PROXY] Redis store connection error: %v", err)
	}
	defer st.Close()

	res, err := resolver.New(cfg, st)
	if err != nil {
		log.Fatalf("[SNI-PROXY] Resolver initialization error: %v", err)
	}

	proxy := sniproxy.New(cfg, res)

	// Trap termination signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.Printf("[SNI-PROXY] Received signal %v, gracefully shutting down...", sig)
		_ = proxy.Close()
	}()

	if err := proxy.Start(); err != nil {
		log.Fatalf("[SNI-PROXY] SNI Proxy stopped: %v", err)
	}
}
