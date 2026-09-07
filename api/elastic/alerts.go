package elastic

import (
	"context"
	"strings"
	"time"
)

// Alert is the API's view of one panoptic-alerts document. Field names/shape
// mirror what ml-service writes (see ml-service/panoptic/alerts.py).
type Alert struct {
	ID          string                 `json:"id"`
	Timestamp   string                 `json:"@timestamp"`
	Event       AlertEvent             `json:"event"`
	Host        AlertHost              `json:"host"`
	User        AlertUser              `json:"user"`
	Process     map[string]interface{} `json:"process,omitempty"`
	Network     map[string]interface{} `json:"network,omitempty"`
	Detection   AlertDetection         `json:"detection"`
	Risk        AlertRisk              `json:"risk"`
	Mitre       []MitreTag             `json:"mitre"`
	Explanation map[string]interface{} `json:"explanation,omitempty"`
	Signals     map[string]interface{} `json:"signals,omitempty"`
	Log         map[string]interface{} `json:"log,omitempty"`
}

type AlertEvent struct {
	ID        string   `json:"id,omitempty"`
	Timestamp string   `json:"timestamp,omitempty"`
	Type      string   `json:"type,omitempty"`
	Action    string   `json:"action,omitempty"`
	Category  []string `json:"category,omitempty"`
	Module    string   `json:"module,omitempty"`
	Outcome   string   `json:"outcome,omitempty"`
}

type AlertHost struct {
	Name        string      `json:"name,omitempty"`
	IP          []string    `json:"ip,omitempty"`
	Criticality interface{} `json:"criticality,omitempty"`
}

type AlertUser struct {
	ID                  interface{} `json:"id,omitempty"`
	Name                string      `json:"name,omitempty"`
	AuditID             interface{} `json:"audit_id,omitempty"`
	AuditName           string      `json:"audit_name,omitempty"`
	IsRoot              bool        `json:"is_root"`
	PrivilegeTransition bool        `json:"privilege_transition"`
}

type AlertDetection struct {
	Model            string   `json:"model"`
	ModelVersion     string   `json:"model_version"`
	DetectionVersion string   `json:"detection_version"`
	AnomalyScore     float64  `json:"anomaly_score"`
	RawScore         float64  `json:"raw_score"`
	Confidence       *float64 `json:"confidence"`
	Prediction       int      `json:"prediction"`
}

type AlertRisk struct {
	Score             int                `json:"score"`
	Severity          string             `json:"severity"`
	Model             string             `json:"model"`
	Impact            float64            `json:"impact"`
	Exploitability    float64            `json:"exploitability"`
	TechnicalSeverity float64            `json:"technical_severity"`
	ContextModifier   float64            `json:"context_modifier"`
	Factors           []string           `json:"factors"`
	Components        map[string]float64 `json:"components,omitempty"`
}

type MitreTag struct {
	Tactic        string  `json:"tactic"`
	TacticID      string  `json:"tactic_id"`
	TechniqueID   string  `json:"technique_id"`
	TechniqueName string  `json:"technique_name"`
	BaseSeverity  float64 `json:"base_severity,omitempty"`
	Confidence    float64 `json:"confidence"`
}

// AlertQuery is the full filter/sort/paginate surface for ListAlerts.
type AlertQuery struct {
	Size        int
	From        int
	SortBy      string // "risk_score" | "detected_at" | "event_time"
	Order       string // "asc" | "desc"
	Severities  []string
	MinScore    *float64
	MaxScore    *float64
	Host        string
	User        string
	EventType   string
	Technique   string
	AnomalyGTE  *float64
	OnlyAnomaly bool
	From_       *time.Time
	To          *time.Time
	Q           string
}

type ListResult struct {
	Total int64   `json:"total"`
	Items []Alert `json:"items"`
}

func (q AlertQuery) filters() []map[string]interface{} {
	var filters []map[string]interface{}

	if len(q.Severities) > 0 {
		filters = append(filters, term("risk.severity", toIface(lower(q.Severities))))
	}
	if q.MinScore != nil || q.MaxScore != nil {
		r := map[string]interface{}{}
		if q.MinScore != nil {
			r["gte"] = *q.MinScore
		}
		if q.MaxScore != nil {
			r["lte"] = *q.MaxScore
		}
		filters = append(filters, rangeq("risk.score", r))
	}
	if q.AnomalyGTE != nil {
		filters = append(filters, rangeq("detection.anomaly_score", map[string]interface{}{"gte": *q.AnomalyGTE}))
	}
	if q.OnlyAnomaly {
		filters = append(filters, map[string]interface{}{"term": map[string]interface{}{"detection.prediction": -1}})
	}
	if q.Host != "" {
		filters = append(filters, map[string]interface{}{"term": map[string]interface{}{"host.name": q.Host}})
	}
	if q.User != "" {
		filters = append(filters, map[string]interface{}{"bool": map[string]interface{}{"should": []map[string]interface{}{
			{"term": map[string]interface{}{"user.name": q.User}},
			{"term": map[string]interface{}{"user.audit_name": q.User}},
		}, "minimum_should_match": 1}})
	}
	if q.EventType != "" {
		filters = append(filters, map[string]interface{}{"term": map[string]interface{}{"event.type": strings.ToUpper(q.EventType)}})
	}
	if q.Technique != "" {
		filters = append(filters, map[string]interface{}{"term": map[string]interface{}{"mitre.technique_id": q.Technique}})
	}
	if q.From_ != nil || q.To != nil {
		r := map[string]interface{}{}
		if q.From_ != nil {
			r["gte"] = q.From_.UTC().Format(time.RFC3339)
		}
		if q.To != nil {
			r["lte"] = q.To.UTC().Format(time.RFC3339)
		}
		filters = append(filters, rangeq("event.timestamp", r))
	}
	if q.Q != "" {
		filters = append(filters, map[string]interface{}{"multi_match": map[string]interface{}{
			"query":  q.Q,
			"type":   "best_fields",
			"fields": []string{"explanation.summary", "explanation.title", "process.command_line", "log.event.original", "log.message"},
		}})
	}
	return filters
}

func (q AlertQuery) body() map[string]interface{} {
	sortField := "risk.score"
	switch q.SortBy {
	case "detected_at":
		sortField = "@timestamp"
	case "event_time":
		sortField = "event.timestamp"
	}
	order := "desc"
	if q.Order == "asc" {
		order = "asc"
	}

	query := map[string]interface{}{"match_all": map[string]interface{}{}}
	if f := q.filters(); len(f) > 0 {
		query = map[string]interface{}{"bool": map[string]interface{}{"filter": f}}
	}

	size := q.Size
	if size <= 0 {
		size = 20
	}
	return map[string]interface{}{
		"from":             q.From,
		"size":             size,
		"track_total_hits": true,
		"sort": []map[string]interface{}{
			{sortField: map[string]interface{}{"order": order}},
			{"@timestamp": map[string]interface{}{"order": "desc"}},
		},
		"query": query,
	}
}

// ListAlerts returns a page of alerts matching q.
func (c *Client) ListAlerts(ctx context.Context, q AlertQuery) (*ListResult, error) {
	res, err := c.search(ctx, q.body())
	if err != nil {
		return nil, err
	}
	items := make([]Alert, 0, len(res.Hits.Hits))
	for _, hit := range res.Hits.Hits {
		items = append(items, hit.toAlert())
	}
	return &ListResult{Total: res.Hits.Total.Value, Items: items}, nil
}

// GetAlert fetches a single alert by Elasticsearch document ID.
func (c *Client) GetAlert(ctx context.Context, id string) (*Alert, error) {
	body := map[string]interface{}{
		"size":  1,
		"query": map[string]interface{}{"ids": map[string]interface{}{"values": []string{id}}},
	}
	res, err := c.search(ctx, body)
	if err != nil {
		return nil, err
	}
	if len(res.Hits.Hits) == 0 {
		return nil, ErrNotFound
	}
	a := res.Hits.Hits[0].toAlert()
	return &a, nil
}

// --- small query-DSL helpers -------------------------------------------------

func term(field string, values []interface{}) map[string]interface{} {
	return map[string]interface{}{"terms": map[string]interface{}{field: values}}
}

func rangeq(field string, spec map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{"range": map[string]interface{}{field: spec}}
}

func toIface(ss []string) []interface{} {
	out := make([]interface{}, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

func lower(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = strings.ToLower(strings.TrimSpace(s))
	}
	return out
}
