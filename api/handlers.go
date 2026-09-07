package main

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/miller-js/Panoptic/api/elastic"
)

type api struct {
	es *elastic.Client
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

// esError maps an Elasticsearch-layer error to an HTTP response.
func esError(w http.ResponseWriter, err error) {
	if errors.Is(err, elastic.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	writeError(w, http.StatusBadGateway, "querying elasticsearch: "+err.Error())
}

// paramFail writes a 400 for a *paramError, returns false otherwise.
func paramFail(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	var pe *paramError
	if errors.As(err, &pe) {
		writeError(w, http.StatusBadRequest, pe.msg)
		return true
	}
	writeError(w, http.StatusBadRequest, err.Error())
	return true
}

func (a *api) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// --- alerts --------------------------------------------------------------

// GET /api/alerts
func (a *api) listAlerts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	size, err := parseSize(q, 20, 100)
	if paramFail(w, err) {
		return
	}
	from, err := parseFrom(q)
	if paramFail(w, err) {
		return
	}
	sortBy, err := parseEnum(q, "sort_by", "risk_score", "detected_at", "event_time")
	if paramFail(w, err) {
		return
	}
	order, err := parseEnum(q, "order", "asc", "desc")
	if paramFail(w, err) {
		return
	}
	severities, err := parseSeverities(q)
	if paramFail(w, err) {
		return
	}
	minScore, err := parseFloatPtr(q, "min_risk_score")
	if paramFail(w, err) {
		return
	}
	maxScore, err := parseFloatPtr(q, "max_risk_score")
	if paramFail(w, err) {
		return
	}
	anomalyGTE, err := parseFloatPtr(q, "min_anomaly_score")
	if paramFail(w, err) {
		return
	}
	onlyAnomaly, err := parseBool(q, "anomaly")
	if paramFail(w, err) {
		return
	}
	fromT, err := parseTimePtr(q, "from_time")
	if paramFail(w, err) {
		return
	}
	toT, err := parseTimePtr(q, "to_time")
	if paramFail(w, err) {
		return
	}

	result, err := a.es.ListAlerts(r.Context(), elastic.AlertQuery{
		Size:        size,
		From:        from,
		SortBy:      sortBy,
		Order:       order,
		Severities:  severities,
		MinScore:    minScore,
		MaxScore:    maxScore,
		AnomalyGTE:  anomalyGTE,
		OnlyAnomaly: onlyAnomaly,
		Host:        q.Get("host"),
		User:        q.Get("user"),
		EventType:   q.Get("event_type"),
		Technique:   q.Get("technique"),
		From_:       fromT,
		To:          toT,
		Q:           q.Get("q"),
	})
	if err != nil {
		esError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// GET /api/alerts/{id}
func (a *api) getAlert(w http.ResponseWriter, r *http.Request) {
	alert, err := a.es.GetAlert(r.Context(), r.PathValue("id"))
	if err != nil {
		esError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, alert)
}

// GET /api/alerts/stats  (also served at /api/stats for back-compat)
func (a *api) alertStats(w http.ResponseWriter, r *http.Request) {
	stats, err := a.es.AlertStats(r.Context())
	if err != nil {
		esError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

// GET /api/anomalies/timeline
func (a *api) timeline(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	interval, err := parseEnum(q, "interval", "5m", "15m", "1h", "3h", "12h", "1d")
	if paramFail(w, err) {
		return
	}
	fromT, err := parseTimePtr(q, "from_time")
	if paramFail(w, err) {
		return
	}
	toT, err := parseTimePtr(q, "to_time")
	if paramFail(w, err) {
		return
	}
	// No artificial default window: the source data set may be historical, so
	// with no bounds the date_histogram simply spans first..last event.
	tl, err := a.es.AnomalyTimeline(r.Context(), interval, fromT, toT)
	if err != nil {
		esError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, tl)
}

// GET /api/risk/distribution
func (a *api) riskDistribution(w http.ResponseWriter, r *http.Request) {
	dist, err := a.es.RiskScoreDistribution(r.Context())
	if err != nil {
		esError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, dist)
}

// GET /api/mitre/techniques
func (a *api) mitreTechniques(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	fromT, err := parseTimePtr(q, "from_time")
	if paramFail(w, err) {
		return
	}
	toT, err := parseTimePtr(q, "to_time")
	if paramFail(w, err) {
		return
	}
	size, err := parseSize(q, 20, 50)
	if paramFail(w, err) {
		return
	}
	techniques, err := a.es.MitreTechniques(r.Context(), fromT, toT, size)
	if err != nil {
		esError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"techniques": techniques})
}

// --- legacy /api/logs (pre-2.0 shape, backed by panoptic-alerts) --------

func (a *api) listLogs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	size, err := parseSize(q, 20, 100)
	if paramFail(w, err) {
		return
	}
	from, err := parseFrom(q)
	if paramFail(w, err) {
		return
	}
	sortBy, err := parseEnum(q, "sort_by", "timestamp", "risk_score")
	if paramFail(w, err) {
		return
	}
	order, err := parseEnum(q, "order", "asc", "desc")
	if paramFail(w, err) {
		return
	}
	minScore, err := parseFloatPtr(q, "min_risk_score")
	if paramFail(w, err) {
		return
	}
	anomaly, err := parseBool(q, "anomaly")
	if paramFail(w, err) {
		return
	}
	result, err := a.es.ListLegacy(r.Context(), elastic.LegacyLogQuery{
		Size:         size,
		From:         from,
		SortBy:       sortBy,
		Order:        order,
		MinRiskScore: minScore,
		AnomalyOnly:  anomaly,
		AuditType:    q.Get("audit_type"),
		Query:        q.Get("q"),
	})
	if err != nil {
		esError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (a *api) getLog(w http.ResponseWriter, r *http.Request) {
	entry, err := a.es.GetLegacy(r.Context(), r.PathValue("id"))
	if err != nil {
		esError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, entry)
}
