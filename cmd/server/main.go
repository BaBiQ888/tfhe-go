package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"tfhe-go/internal/httpapi"
	"tfhe-go/internal/tfhe"
)

func main() {
	booleanService, err := tfhe.NewBooleanService()
	if err != nil {
		log.Fatalf("failed to init tfhe boolean service: %v", err)
	}
	defer booleanService.Close()

	uint8Service, err := tfhe.NewUint8Service()
	if err != nil {
		log.Fatalf("failed to init tfhe uint8 service: %v", err)
	}
	defer uint8Service.Close()

	mux := http.NewServeMux()
	handler := httpapi.NewHandler(booleanService, uint8Service)
	handler.Register(mux)

	addr := ":8080"
	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		log.Printf("tfhe-go server listening on %s", addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Printf("graceful shutdown failed: %v", err)
	}
}
