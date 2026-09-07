package main

import (
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/miller-js/Panoptic/api/elastic"
)

func main() {
	esClient, err := elastic.NewClient()
	if err != nil {
		log.Fatalf("failed to create elasticsearch client: %v", err)
	}

	a := &api{es: esClient}

	addr := ":" + getenv("PORT", "8080")
	log.Printf("panoptic api listening on %s (alerts index: %s)", addr, esClient.AlertsIndex())
	log.Fatal(http.ListenAndServe(addr, withCORS(routes(a))))
}

func routes(a *api) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", a.health)

	// v2 alert API
	mux.HandleFunc("GET /api/alerts", a.listAlerts)
	mux.HandleFunc("GET /api/alerts/stats", a.alertStats)
	mux.HandleFunc("GET /api/alerts/{id}", a.getAlert)
	mux.HandleFunc("GET /api/anomalies/timeline", a.timeline)
	mux.HandleFunc("GET /api/risk/distribution", a.riskDistribution)
	mux.HandleFunc("GET /api/mitre/techniques", a.mitreTechniques)

	// pre-2.0 compatibility surface
	mux.HandleFunc("GET /api/stats", a.alertStats)
	mux.HandleFunc("GET /api/logs", a.listLogs)
	mux.HandleFunc("GET /api/logs/{id}", a.getLog)

	return mux
}

// withCORS allows the configured origins (default "*" for local dev).
func withCORS(next http.Handler) http.Handler {
	origins := getenv("PANOPTIC_CORS_ORIGINS", "*")
	allowed := strings.Split(origins, ",")

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		switch {
		case origins == "*":
			w.Header().Set("Access-Control-Allow-Origin", "*")
		case origin != "" && contains(allowed, origin):
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func contains(ss []string, v string) bool {
	for _, s := range ss {
		if strings.TrimSpace(s) == v {
			return true
		}
	}
	return false
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
