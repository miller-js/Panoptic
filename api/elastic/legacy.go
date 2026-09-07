package elastic

import "context"

// LegacyLogEntry is the pre-2.0 /api/logs response shape, kept so existing API
// consumers don't break when the backing index moves to panoptic-alerts. New
// code should use Alert / ListAlerts instead.
type LegacyLogEntry struct {
	ID           string                 `json:"id"`
	Timestamp    string                 `json:"timestamp"`
	LogTimestamp string                 `json:"log_timestamp,omitempty"`
	Model        string                 `json:"model"`
	Prediction   int                    `json:"prediction"`
	RiskScore    float64                `json:"risk_score"`
	Confidence   *float64               `json:"confidence"`
	Severity     string                 `json:"severity"`
	Hostname     string                 `json:"hostname,omitempty"`
	AuditType    string                 `json:"audit_type,omitempty"`
	Message      string                 `json:"message,omitempty"`
	Log          map[string]interface{} `json:"log"`
}

type LegacyListResult struct {
	Total int64            `json:"total"`
	Items []LegacyLogEntry `json:"items"`
}

func (a Alert) toLegacy() LegacyLogEntry {
	msg := ""
	if a.Process != nil {
		if cl, ok := a.Process["command_line"].(string); ok {
			msg = cl
		}
	}
	if msg == "" && a.Log != nil {
		if ev, ok := a.Log["event"].(map[string]interface{}); ok {
			if orig, ok := ev["original"].(string); ok {
				msg = orig
			}
		}
		if msg == "" {
			if m, ok := a.Log["message"].(string); ok {
				msg = m
			}
		}
	}
	return LegacyLogEntry{
		ID:           a.ID,
		Timestamp:    a.Timestamp,
		LogTimestamp: a.Event.Timestamp,
		Model:        a.Detection.Model,
		Prediction:   a.Detection.Prediction,
		RiskScore:    float64(a.Risk.Score),
		Confidence:   a.Detection.Confidence,
		Severity:     a.Risk.Severity,
		Hostname:     a.Host.Name,
		AuditType:    a.Event.Type,
		Message:      msg,
		Log:          a.Log,
	}
}

// LegacyLogQuery mirrors the old /api/logs params.
type LegacyLogQuery struct {
	Size         int
	From         int
	SortBy       string // "timestamp" | "risk_score"
	Order        string
	MinRiskScore *float64
	AnomalyOnly  bool
	AuditType    string
	Query        string
}

func (c *Client) ListLegacy(ctx context.Context, q LegacyLogQuery) (*LegacyListResult, error) {
	sortBy := "event_time"
	if q.SortBy == "risk_score" {
		sortBy = "risk_score"
	}
	aq := AlertQuery{
		Size:        q.Size,
		From:        q.From,
		SortBy:      sortBy,
		Order:       q.Order,
		MinScore:    q.MinRiskScore,
		OnlyAnomaly: q.AnomalyOnly,
		EventType:   q.AuditType,
		Q:           q.Query,
	}
	res, err := c.ListAlerts(ctx, aq)
	if err != nil {
		return nil, err
	}
	out := &LegacyListResult{Total: res.Total, Items: make([]LegacyLogEntry, 0, len(res.Items))}
	for _, a := range res.Items {
		out.Items = append(out.Items, a.toLegacy())
	}
	return out, nil
}

func (c *Client) GetLegacy(ctx context.Context, id string) (*LegacyLogEntry, error) {
	a, err := c.GetAlert(ctx, id)
	if err != nil {
		return nil, err
	}
	e := a.toLegacy()
	return &e, nil
}
