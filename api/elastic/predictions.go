package elastic

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
)

const predictionsIndex = "panoptic-predictions"

// LogEntry is the API's view of one panoptic-predictions document: the
// ML-enhanced fields plus a few convenience fields flattened out of the
// nested original log, alongside the full original log for drill-down.
type LogEntry struct {
	ID           string                 `json:"id"`
	Timestamp    string                 `json:"timestamp"`               // when the prediction was made
	LogTimestamp string                 `json:"log_timestamp,omitempty"` // original log's @timestamp
	Model        string                 `json:"model"`
	Prediction   int                    `json:"prediction"` // 1 = normal, -1 = anomaly (IsolationForest)
	RiskScore    float64                `json:"risk_score"` // 0-100, higher = more anomalous
	Confidence   *float64               `json:"confidence"`
	Hostname     string                 `json:"hostname,omitempty"`
	AuditType    string                 `json:"audit_type,omitempty"` // e.g. "BPF", "SYSCALL", "PATH"
	Message      string                 `json:"message,omitempty"`    // raw audit line
	Log          map[string]interface{} `json:"log"`                  // full original source document
}

// ListOptions controls filtering, sorting, and pagination for List.
type ListOptions struct {
	Size         int
	From         int
	SortBy       string // "risk_score" | "timestamp"
	Order        string // "asc" | "desc"
	MinRiskScore *float64
	AnomalyOnly  bool
	AuditType    string
	Query        string // free-text search over the raw audit message
}

// ListResult is a page of log entries plus the total number matching.
type ListResult struct {
	Total int64      `json:"total"`
	Items []LogEntry `json:"items"`
}

// List returns a page of ML-enhanced logs matching opts.
func (c *Client) List(ctx context.Context, opts ListOptions) (*ListResult, error) {
	sortField := "@timestamp"
	if opts.SortBy == "risk_score" {
		sortField = "risk_score"
	}

	order := "desc"
	if opts.Order == "asc" {
		order = "asc"
	}

	var filters []map[string]interface{}

	if opts.MinRiskScore != nil {
		filters = append(filters, map[string]interface{}{
			"range": map[string]interface{}{
				"risk_score": map[string]interface{}{"gte": *opts.MinRiskScore},
			},
		})
	}

	if opts.AnomalyOnly {
		filters = append(filters, map[string]interface{}{
			"term": map[string]interface{}{"prediction": -1},
		})
	}

	if opts.AuditType != "" {
		filters = append(filters, map[string]interface{}{
			"term": map[string]interface{}{"log.parsed.type.keyword": opts.AuditType},
		})
	}

	if opts.Query != "" {
		filters = append(filters, map[string]interface{}{
			"multi_match": map[string]interface{}{
				"query":  opts.Query,
				"fields": []string{"log.message", "log.event.original"},
			},
		})
	}

	query := map[string]interface{}{"match_all": map[string]interface{}{}}
	if len(filters) > 0 {
		query = map[string]interface{}{"bool": map[string]interface{}{"filter": filters}}
	}

	body := map[string]interface{}{
		"from":             opts.From,
		"size":             opts.Size,
		"track_total_hits": true,
		"sort":             []map[string]interface{}{{sortField: map[string]interface{}{"order": order}}},
		"query":            query,
	}

	res, err := c.search(ctx, body)
	if err != nil {
		return nil, err
	}

	entries := make([]LogEntry, 0, len(res.Hits.Hits))
	for _, hit := range res.Hits.Hits {
		entries = append(entries, toLogEntry(hit))
	}

	return &ListResult{Total: res.Hits.Total.Value, Items: entries}, nil
}

// Get fetches a single log entry by its Elasticsearch document ID.
func (c *Client) Get(ctx context.Context, id string) (*LogEntry, error) {
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

	entry := toLogEntry(res.Hits.Hits[0])
	return &entry, nil
}

// Stats holds a summary of the panoptic-predictions index for an
// at-a-glance dashboard view.
type Stats struct {
	Total        int64   `json:"total"`
	AnomalyCount int64   `json:"anomaly_count"`
	AvgRiskScore float64 `json:"avg_risk_score"`
	MaxRiskScore float64 `json:"max_risk_score"`
}

// GetStats summarizes the predictions currently in Elasticsearch.
func (c *Client) GetStats(ctx context.Context) (*Stats, error) {
	body := map[string]interface{}{
		"size":             0,
		"track_total_hits": true,
		"aggs": map[string]interface{}{
			"avg_risk_score": map[string]interface{}{"avg": map[string]interface{}{"field": "risk_score"}},
			"max_risk_score": map[string]interface{}{"max": map[string]interface{}{"field": "risk_score"}},
			"anomalies":      map[string]interface{}{"filter": map[string]interface{}{"term": map[string]interface{}{"prediction": -1}}},
		},
	}

	res, err := c.search(ctx, body)
	if err != nil {
		return nil, err
	}

	return &Stats{
		Total:        res.Hits.Total.Value,
		AnomalyCount: res.Aggregations.Anomalies.DocCount,
		AvgRiskScore: res.Aggregations.AvgRiskScore.Value,
		MaxRiskScore: res.Aggregations.MaxRiskScore.Value,
	}, nil
}

func toLogEntry(hit searchHit) LogEntry {
	entry := LogEntry{
		ID:         hit.ID,
		Timestamp:  hit.Source.Timestamp,
		Model:      hit.Source.Model,
		Prediction: hit.Source.Prediction,
		RiskScore:  hit.Source.RiskScore,
		Confidence: hit.Source.Confidence,
		Log:        hit.Source.Log,
	}

	if ts, ok := hit.Source.Log["@timestamp"].(string); ok {
		entry.LogTimestamp = ts
	}

	if host, ok := hit.Source.Log["host"].(map[string]interface{}); ok {
		if hostname, ok := host["hostname"].(string); ok {
			entry.Hostname = hostname
		}
	}

	if parsed, ok := hit.Source.Log["parsed"].(map[string]interface{}); ok {
		if auditType, ok := parsed["type"].(string); ok {
			entry.AuditType = auditType
		}
	}

	if msg, ok := hit.Source.Log["message"].(string); ok && msg != "" {
		entry.Message = msg
	} else if event, ok := hit.Source.Log["event"].(map[string]interface{}); ok {
		if original, ok := event["original"].(string); ok {
			entry.Message = original
		}
	}

	return entry
}

// --- raw Elasticsearch response shapes ---

type predictionSource struct {
	Timestamp  string                 `json:"@timestamp"`
	Model      string                 `json:"model"`
	Prediction int                    `json:"prediction"`
	RiskScore  float64                `json:"risk_score"`
	Confidence *float64               `json:"confidence"`
	Log        map[string]interface{} `json:"log"`
}

type searchHit struct {
	ID     string           `json:"_id"`
	Source predictionSource `json:"_source"`
}

type searchResponse struct {
	Hits struct {
		Total struct {
			Value int64 `json:"value"`
		} `json:"total"`
		Hits []searchHit `json:"hits"`
	} `json:"hits"`
	Aggregations struct {
		AvgRiskScore struct {
			Value float64 `json:"value"`
		} `json:"avg_risk_score"`
		MaxRiskScore struct {
			Value float64 `json:"value"`
		} `json:"max_risk_score"`
		Anomalies struct {
			DocCount int64 `json:"doc_count"`
		} `json:"anomalies"`
	} `json:"aggregations"`
}

// ErrNotFound is returned by Get when no document matches the given ID.
var ErrNotFound = fmt.Errorf("not found")

func (c *Client) search(ctx context.Context, body map[string]interface{}) (*searchResponse, error) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(body); err != nil {
		return nil, err
	}

	res, err := c.es.Search(
		c.es.Search.WithContext(ctx),
		c.es.Search.WithIndex(predictionsIndex),
		c.es.Search.WithBody(&buf),
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("elasticsearch returned %s", res.Status())
	}

	var parsed searchResponse
	if err := json.NewDecoder(res.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("decoding elasticsearch response: %w", err)
	}

	return &parsed, nil
}
