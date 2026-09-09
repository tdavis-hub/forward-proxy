package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	dataDir := flag.String("data", envOr("DATA_DIR", "/data"), "data directory for config and activity logs")
	flag.Parse()

	store, err := NewStore(*dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "forward-proxy: %v\n", err)
		os.Exit(1)
	}
	proxy := NewProxy(store, *dataDir)
	store.AddOnChange(proxy.OnConfigChanged)

	// Periodic flush of in-memory stats to the config file.
	stop := make(chan struct{})
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				proxy.FlushStats()
			case <-stop:
				return
			}
		}
	}()

	if err := proxy.Start(store.Config()); err != nil {
		fmt.Fprintf(os.Stderr, "forward-proxy: %v\n", err)
		os.Exit(1)
	}

	cfg := store.Config()
	fmt.Printf("forward-proxy v%s started\n", Version)
	fmt.Printf("  proxy  : http%s/  (forward proxy for HTTP + CONNECT)\n", cfg.Proxy.ListenAddr)
	fmt.Printf("  admin  : http%s/admin\n", cfg.Proxy.AdminListenAddr)
	for i := range cfg.Users {
		if cfg.Users[i].Username == "admin" && IsDefaultPassword(cfg.Users[i].PasswordHash) {
			fmt.Println("  NOTICE : default admin credentials admin/admin123 are active — change them in the admin UI")
			break
		}
	}
	fmt.Printf("  data   : %s\n", *dataDir)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	fmt.Println("\nshutting down...")
	close(stop)
	proxy.Shutdown()
}
