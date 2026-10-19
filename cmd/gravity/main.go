package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"gravity-dns/internal/config"
	"gravity-dns/internal/dnsengine"
	"gravity-dns/internal/limiter"
	"gravity-dns/internal/panel"
	"gravity-dns/internal/resolver"
	"gravity-dns/internal/sniproxy"
	"gravity-dns/internal/store"
)

const version = "1.0.0-production"

func printUsage() {
	fmt.Printf(`GravityDNS - High-Performance SmartDNS + SNI Proxy Platform (%s)

Usage:
  gravity <command> [flags]

Commands:
  all         Run all services (DNS Engine, SNI Proxy, and Web Panel) concurrently
  dns         Run pure Go DoT & DoH DNS Engine (:853, :8443)
  sniproxy    Run pure Go transparent TLS SNI router (:443)
  panel       Run Admin Web Panel & Management REST API (:8080)
  version     Display version information

Flags:
  -config string   Path to gravity.yaml configuration file
`, version)
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	configPath := fs.String("config", "", "Path to gravity.yaml configuration file")
	_ = fs.Parse(args)

	switch cmd {
	case "version", "-v", "--version":
		fmt.Printf("GravityDNS version %s\n", version)
		return

	case "all":
		runAll(*configPath)

	case "dns":
		runDNS(*configPath)

	case "sniproxy":
		runSNIProxy(*configPath)

	case "panel":
		runPanel(*configPath)

	default:
		fmt.Printf("Unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func runAll(cfgPath string) {
	log.Printf("[GRAVITY] Starting unified GravityDNS platform (%s)...", version)

	cfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		log.Fatalf("[GRAVITY] Config error: %v", err)
	}

	st, err := store.New(&cfg.Redis)
	if err != nil {
		log.Fatalf("[GRAVITY] Redis error: %v", err)
	}
	defer st.Close()

	if err := st.SeedPresetRules(context.Background()); err != nil {
		log.Printf("[GRAVITY] Preset seeding: %v", err)
	}

	lim := limiter.New(st.Client(), st, cfg.DNS.DeviceWindowSec)
	res, err := resolver.New(cfg, st)
	if err != nil {
		log.Fatalf("[GRAVITY] Resolver error: %v", err)
	}

	dnsEng, err := dnsengine.New(cfg, st, lim, res)
	if err != nil {
		log.Fatalf("[GRAVITY] DNS Engine error: %v", err)
	}

	sniEng := sniproxy.New(cfg, res)
	panelEng := panel.NewServer(cfg, st, res)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.Printf("[GRAVITY] Received signal %v. Initiating graceful shutdown...", sig)
		_ = dnsEng.Close()
		_ = sniEng.Close()
		_ = panelEng.Close()
		os.Exit(0)
	}()

	// 1. Launch DNS Engine in goroutine
	if cfg.DNS.Enabled {
		go func() {
			if err := dnsEng.Start(); err != nil {
				log.Fatalf("[GRAVITY] DNS Engine failed: %v", err)
			}
		}()
	}

	// 2. Launch SNI Proxy in goroutine
	if cfg.SNIProxy.Enabled {
		go func() {
			if err := sniEng.Start(); err != nil {
				log.Fatalf("[GRAVITY] SNI Proxy failed: %v", err)
			}
		}()
	}

	// 3. Launch Web Panel on main thread
	if cfg.Panel.Enabled {
		if err := panelEng.Start(); err != nil {
			log.Fatalf("[GRAVITY] Web Panel failed: %v", err)
		}
	} else {
		// Wait indefinitely if panel disabled
		select {}
	}
}

func runDNS(cfgPath string) {
	cfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		log.Fatalf("[DNS] Config error: %v", err)
	}
	st, err := store.New(&cfg.Redis)
	if err != nil {
		log.Fatalf("[DNS] Redis error: %v", err)
	}
	defer st.Close()

	_ = st.SeedPresetRules(context.Background())
	lim := limiter.New(st.Client(), st, cfg.DNS.DeviceWindowSec)
	res, err := resolver.New(cfg, st)
	if err != nil {
		log.Fatalf("[DNS] Resolver error: %v", err)
	}
	engine, err := dnsengine.New(cfg, st, lim, res)
	if err != nil {
		log.Fatalf("[DNS] Engine error: %v", err)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		_ = engine.Close()
	}()

	_ = engine.Start()
}

func runSNIProxy(cfgPath string) {
	cfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		log.Fatalf("[SNI] Config error: %v", err)
	}
	st, err := store.New(&cfg.Redis)
	if err != nil {
		log.Fatalf("[SNI] Redis error: %v", err)
	}
	defer st.Close()

	res, err := resolver.New(cfg, st)
	if err != nil {
		log.Fatalf("[SNI] Resolver error: %v", err)
	}
	proxy := sniproxy.New(cfg, res)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		_ = proxy.Close()
	}()

	_ = proxy.Start()
}

func runPanel(cfgPath string) {
	cfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		log.Fatalf("[PANEL] Config error: %v", err)
	}
	st, err := store.New(&cfg.Redis)
	if err != nil {
		log.Fatalf("[PANEL] Redis error: %v", err)
	}
	defer st.Close()

	res, err := resolver.New(cfg, st)
	if err != nil {
		log.Fatalf("[PANEL] Resolver error: %v", err)
	}
	server := panel.NewServer(cfg, st, res)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		_ = server.Close()
	}()

	_ = server.Start()
}
