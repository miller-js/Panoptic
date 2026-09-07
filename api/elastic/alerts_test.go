package elastic

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

const oneAlertHit = `{
  "hits": {"total": {"value": 1}, "hits": [
    {"_id": "abc", "_source": {
      "@timestamp": "2026-07-14T23:27:40Z",
      "event": {"id": "47679", "timestamp": "2026-07-14T23:27:29Z", "type": "SYSCALL", "action": "execve"},
      "host": {"name": "LinuxEndpoint", "criticality": 0.5},
      "user": {"id": 0, "name": "root", "audit_name": "stickyrice", "is_root": true, "privilege_transition": true},
      "process": {"name": "sudo", "command_line": "sudo su -"},
      "detection": {"model": "isolation_forest", "anomaly_score": 0.94, "confidence": 0.9, "prediction": -1},
      "risk": {"score": 78, "severity": "high", "factors": ["privilege_transition"]},
      "mitre": [{"technique_id": "T1548.003", "technique_name": "Sudo", "tactic": "Privilege Escalation", "confidence": 0.8}],
      "explanation": {"title": "Privilege escalation", "summary": "sudo by root"}
    }}
  ]}
}`

func filterList(t *testing.T, body map[string]interface{}) []interface{} {
	t.Helper()
	q, _ := nestedAny(body, "query", "bool", "filter")
	list, ok := q.([]interface{})
	if !ok {
		t.Fatalf("expected bool.filter list, got %T (%v)", q, body["query"])
	}
	return list
}

func TestListAlertsDecodesDocument(t *testing.T) {
	fake := &fakeES{response: oneAlertHit}
	c := newTestClient(t, fake)

	res, err := c.ListAlerts(context.Background(), AlertQuery{Size: 10})
	if err != nil {
		t.Fatalf("ListAlerts: %v", err)
	}
	if res.Total != 1 || len(res.Items) != 1 {
		t.Fatalf("want 1 item, got total=%d items=%d", res.Total, len(res.Items))
	}
	a := res.Items[0]
	if a.ID != "abc" || a.Risk.Score != 78 || a.Risk.Severity != "high" {
		t.Fatalf("bad decode: %+v", a.Risk)
	}
	if len(a.Mitre) != 1 || a.Mitre[0].TechniqueID != "T1548.003" {
		t.Fatalf("mitre not decoded: %+v", a.Mitre)
	}
	if a.Detection.Prediction != -1 {
		t.Fatalf("prediction: %d", a.Detection.Prediction)
	}
}

func TestListAlertsBuildsFilters(t *testing.T) {
	fake := &fakeES{response: `{"hits":{"total":{"value":0},"hits":[]}}`}
	c := newTestClient(t, fake)

	min := 40.0
	from := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	_, err := c.ListAlerts(context.Background(), AlertQuery{
		Size:       25,
		Severities: []string{"High", "critical"},
		MinScore:   &min,
		Host:       "web1",
		Technique:  "T1059.004",
		From_:      &from,
		Q:          "reverse shell",
	})
	if err != nil {
		t.Fatalf("ListAlerts: %v", err)
	}

	filters := filterList(t, fake.lastBody)
	if len(filters) != 6 {
		t.Fatalf("expected 6 filters, got %d: %v", len(filters), filters)
	}

	// severity terms lower-cased
	var sawSeverity, sawTechnique, sawRange, sawText bool
	for _, f := range filters {
		fm := f.(map[string]interface{})
		if terms, ok := fm["terms"].(map[string]interface{}); ok {
			if v, ok := terms["risk.severity"].([]interface{}); ok {
				sawSeverity = true
				if v[0] != "high" || v[1] != "critical" {
					t.Fatalf("severities not normalised: %v", v)
				}
			}
		}
		if term, ok := fm["term"].(map[string]interface{}); ok {
			if term["mitre.technique_id"] == "T1059.004" {
				sawTechnique = true
			}
		}
		if rng, ok := fm["range"].(map[string]interface{}); ok {
			if _, ok := rng["risk.score"]; ok {
				sawRange = true
			}
		}
		if _, ok := fm["multi_match"]; ok {
			sawText = true
		}
	}
	if !sawSeverity || !sawTechnique || !sawRange || !sawText {
		t.Fatalf("missing a filter: sev=%v tech=%v range=%v text=%v", sawSeverity, sawTechnique, sawRange, sawText)
	}
}

func TestListAlertsSortMapping(t *testing.T) {
	fake := &fakeES{response: `{"hits":{"total":{"value":0},"hits":[]}}`}
	c := newTestClient(t, fake)
	_, _ = c.ListAlerts(context.Background(), AlertQuery{SortBy: "event_time", Order: "asc"})

	sortRaw, _ := json.Marshal(fake.lastBody["sort"])
	if got := string(sortRaw); got != `[{"event.timestamp":{"order":"asc"}},{"@timestamp":{"order":"desc"}}]` {
		t.Fatalf("sort body = %s", got)
	}
}

func TestGetAlertNotFound(t *testing.T) {
	fake := &fakeES{response: `{"hits":{"total":{"value":0},"hits":[]}}`}
	c := newTestClient(t, fake)
	_, err := c.GetAlert(context.Background(), "missing")
	if err != ErrNotFound {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestSearchPropagatesESError(t *testing.T) {
	fake := &fakeES{status: 500, response: `{"error":"boom"}`}
	c := newTestClient(t, fake)
	_, err := c.ListAlerts(context.Background(), AlertQuery{})
	if err == nil {
		t.Fatal("expected error on ES 500")
	}
}

func TestStatsParsesAggregations(t *testing.T) {
	fake := &fakeES{response: `{
	  "hits": {"total": {"value": 1200}},
	  "aggregations": {
	    "avg_risk": {"value": 33.33},
	    "max_risk": {"value": 91},
	    "anomalies": {"doc_count": 47},
	    "last_24h": {"doc_count": 5},
	    "by_severity": {"buckets": [
	      {"key": "low", "doc_count": 900},
	      {"key": "high", "doc_count": 40}
	    ]}
	  }
	}`}
	c := newTestClient(t, fake)
	s, err := c.AlertStats(context.Background())
	if err != nil {
		t.Fatalf("AlertStats: %v", err)
	}
	if s.Total != 1200 || s.AnomalyCount != 47 || s.MaxRiskScore != 91 {
		t.Fatalf("bad stats: %+v", s)
	}
	if s.AvgRiskScore != 33.3 {
		t.Fatalf("avg not rounded: %v", s.AvgRiskScore)
	}
	if s.BySeverity["low"] != 900 || s.BySeverity["high"] != 40 {
		t.Fatalf("by_severity: %v", s.BySeverity)
	}
}

func TestRiskDistributionAlwaysReturnsFiveBands(t *testing.T) {
	fake := &fakeES{response: `{
	  "hits": {"total": {"value": 10}},
	  "aggregations": {"bands": {"buckets": [
	    {"key": "low", "doc_count": 6},
	    {"key": "high", "doc_count": 4}
	  ]}}
	}`}
	c := newTestClient(t, fake)
	d, err := c.RiskScoreDistribution(context.Background())
	if err != nil {
		t.Fatalf("RiskScoreDistribution: %v", err)
	}
	if len(d.Bands) != 5 {
		t.Fatalf("want 5 bands, got %d", len(d.Bands))
	}
	if d.Bands[1].Severity != "low" || d.Bands[1].Count != 6 {
		t.Fatalf("low band: %+v", d.Bands[1])
	}
	if d.Bands[0].Count != 0 {
		t.Fatalf("informational band should be zero-filled, got %d", d.Bands[0].Count)
	}
}

func TestMitreTechniquesFlattensSubAggs(t *testing.T) {
	fake := &fakeES{response: `{
	  "hits": {"total": {"value": 3}},
	  "aggregations": {"techniques": {"buckets": [
	    {"key": "T1059.004", "doc_count": 12,
	     "name": {"buckets": [{"key": "Unix Shell", "doc_count": 12}]},
	     "tactic": {"buckets": [{"key": "Execution", "doc_count": 12}]},
	     "max_conf": {"value": 0.85}}
	  ]}}
	}`}
	c := newTestClient(t, fake)
	techniques, err := c.MitreTechniques(context.Background(), nil, nil, 10)
	if err != nil {
		t.Fatalf("MitreTechniques: %v", err)
	}
	if len(techniques) != 1 {
		t.Fatalf("want 1 technique, got %d", len(techniques))
	}
	got := techniques[0]
	if got.TechniqueID != "T1059.004" || got.TechniqueName != "Unix Shell" || got.Tactic != "Execution" {
		t.Fatalf("bad technique: %+v", got)
	}
	if got.Count != 12 || got.MaxConfidence != 0.85 {
		t.Fatalf("bad counts: %+v", got)
	}
}

func TestTimelineDecodesBuckets(t *testing.T) {
	fake := &fakeES{response: `{
	  "hits": {"total": {"value": 2}},
	  "aggregations": {"timeline": {"buckets": [
	    {"key_as_string": "2026-07-14T00:00:00Z", "doc_count": 10,
	     "anomalies": {"doc_count": 2}, "high": {"doc_count": 1}}
	  ]}}
	}`}
	c := newTestClient(t, fake)
	tl, err := c.AnomalyTimeline(context.Background(), "1h", nil, nil)
	if err != nil {
		t.Fatalf("AnomalyTimeline: %v", err)
	}
	if len(tl.Buckets) != 1 || tl.Buckets[0].Total != 10 || tl.Buckets[0].Anomalies != 2 || tl.Buckets[0].High != 1 {
		t.Fatalf("bad timeline: %+v", tl.Buckets)
	}
}

func TestLegacyMappingPreservesOldShape(t *testing.T) {
	fake := &fakeES{response: oneAlertHit}
	c := newTestClient(t, fake)
	res, err := c.ListLegacy(context.Background(), LegacyLogQuery{Size: 5})
	if err != nil {
		t.Fatalf("ListLegacy: %v", err)
	}
	item := res.Items[0]
	if item.RiskScore != 78 || item.Prediction != -1 || item.Hostname != "LinuxEndpoint" || item.AuditType != "SYSCALL" {
		t.Fatalf("legacy shape wrong: %+v", item)
	}
	if item.Message != "sudo su -" {
		t.Fatalf("legacy message: %q", item.Message)
	}
}
