package main

import (
	"log"
	"net/http"
	"os"

	"github.com/miller-js/Panoptic/api/elastic"
)

func main() {
	esClient, err := elastic.NewClient()
	if err != nil {
		log.Fatalf("failed to create elasticsearch client: %v", err)
	}

	a := &api{es: esClient}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", a.health)
	mux.HandleFunc("GET /api/logs", a.listLogs)
	mux.HandleFunc("GET /api/logs/{id}", a.getLog)
	mux.HandleFunc("GET /api/stats", a.stats)

	addr := ":" + getenv("PORT", "8080")

	log.Printf("panoptic api listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, withCORS(mux)))
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
