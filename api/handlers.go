package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/miller-js/Panoptic/api/elastic"
)

type api struct {
	es *elastic.Client
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func (a *api) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// listLogs handles GET /api/logs
func (a *api) listLogs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	size := 20
	if v := q.Get("size"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, "size must be a positive integer")
			return
		}
		size = n
	}
	if size > 100 {
		size = 100
	}

	from := 0
	if v := q.Get("from"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			writeError(w, http.StatusBadRequest, "from must be a non-negative integer")
			return
		}
		from = n
	}

	sortBy := q.Get("sort_by")
	if sortBy != "" && sortBy != "risk_score" && sortBy != "timestamp" {
		writeError(w, http.StatusBadRequest, "sort_by must be 'risk_score' or 'timestamp'")
		return
	}

	order := q.Get("order")
	if order != "" && order != "asc" && order != "desc" {
		writeError(w, http.StatusBadRequest, "order must be 'asc' or 'desc'")
		return
	}

	opts := elastic.ListOptions{
		Size:      size,
		From:      from,
		SortBy:    sortBy,
		Order:     order,
		AuditType: q.Get("audit_type"),
		Query:     q.Get("q"),
	}

	if v := q.Get("min_risk_score"); v != "" {
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "min_risk_score must be a number")
			return
		}
		opts.MinRiskScore = &f
	}

	if v := q.Get("anomaly"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "anomaly must be true or false")
			return
		}
		opts.AnomalyOnly = b
	}

	result, err := a.es.List(r.Context(), opts)
	if err != nil {
		writeError(w, http.StatusBadGateway, "querying elasticsearch: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// getLog handles GET /api/logs/{id}
func (a *api) getLog(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	entry, err := a.es.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, elastic.ErrNotFound) {
			writeError(w, http.StatusNotFound, "no log found with that id")
			return
		}
		writeError(w, http.StatusBadGateway, "querying elasticsearch: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, entry)
}

// stats handles GET /api/stats
func (a *api) stats(w http.ResponseWriter, r *http.Request) {
	result, err := a.es.GetStats(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, "querying elasticsearch: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, result)
}
