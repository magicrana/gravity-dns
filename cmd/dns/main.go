package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"gravity-dns/internal/config"
	"gravity-dns/internal/dnsengine"
	"gravity-dns/internal/limiter"
	"gravity-dns/internal/resolver"
	"gravity-dns/internal/store"
)

func main() {
	configPath := flag.String("config", "", "Path to gravity.yaml configuration file")
	flag.Parse()

	log.Println("[DNS] Starting GravityDNS Engine...")

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("[DNS] Configuration error: %v", err)
	}

	st, err := store.New(&cfg.Redis)
	if err != nil {
		log.Fatalf("[DNS] Redis store connection error: %v", err)
	}
	defer st.Close()

	// Seed streaming presets if needed
	if err := st.SeedPresetRules(context.Background()); err != nil {
		log.Printf("[DNS] Preset seeding note: %v", err)
	}

	lim := limiter.New(st.Client(), st, cfg.DNS.DeviceWindowSec)

	res, err := resolver.New(cfg, st)
	if err != nil {
		log.Fatalf("[DNS] Resolver initialization error: %v", err)
	}

	engine, err := dnsengine.New(cfg, st, lim, res)
	if err != nil {
		log.Fatalf("[DNS] DNS Engine initialization error: %v", err)
	}

	// Trap termination signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.Printf("[DNS] Received signal %v, gracefully shutting down...", sig)
		_ = engine.Close()
	}()

	if err := engine.Start(); err != nil {
		log.Fatalf("[DNS] Server execution stopped: %v", err)
	}
}
