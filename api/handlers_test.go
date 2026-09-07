package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/miller-js/Panoptic/api/elastic"
)

// respTransport serves one canned Elasticsearch response for every request.
type respTransport struct {
	status   int
	body     string
	lastPath string
}

func (r *respTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r.lastPath = req.URL.Path
	st := r.status
	if st == 0 {
		st = 200
	}
	return &http.Response{
		StatusCode: st,
		Header:     http.Header{"X-Elastic-Product": []string{"Elasticsearch"}, "Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewBufferString(r.body)),
		Request:    req,
	}, nil
}

func newTestAPI(t *testing.T, status int, body string) (*api, *respTransport) {
	t.Helper()
	st := &respTransport{status: status, body: body}
	c, err := elastic.NewClientWithConfig(elastic.Config{
		Addresses: []string{"http://es.test:9200"},
		Transport: st,
	})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	return &api{es: c}, st
}

func do(a *api, method, target string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	rr := httptest.NewRecorder()
	routes(a).ServeHTTP(rr, req)
	return rr
}

func TestHealth(t *testing.T) {
	a, _ := newTestAPI(t, 200, `{}`)
	rr := do(a, "GET", "/health")
	if rr.Code != 200 {
		t.Fatalf("health: %d", rr.Code)
	}
}

func TestListAlertsHappyPath(t *testing.T) {
	a, _ := newTestAPI(t, 200, `{"hits":{"total":{"value":2},"hits":[
	  {"_id":"a1","_source":{"risk":{"score":80,"severity":"critical"},"detection":{"prediction":-1},"mitre":[]}},
	  {"_id":"a2","_source":{"risk":{"score":22,"severity":"low"},"detection":{"prediction":1},"mitre":[]}}
	]}}`)
	rr := do(a, "GET", "/api/alerts?size=10&severity=critical,low&sort_by=risk_score")
	if rr.Code != 200 {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	var out struct {
		Total int64 `json:"total"`
		Items []struct {
			ID   string `json:"id"`
			Risk struct {
				Score int `json:"score"`
			} `json:"risk"`
		} `json:"items"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Total != 2 || len(out.Items) != 2 || out.Items[0].ID != "a1" {
		t.Fatalf("bad body: %s", rr.Body.String())
	}
}

func TestListAlertsRejectsBadParams(t *testing.T) {
	a, _ := newTestAPI(t, 200, `{"hits":{"total":{"value":0},"hits":[]}}`)
	cases := []string{
		"/api/alerts?size=-1",
		"/api/alerts?size=abc",
		"/api/alerts?sort_by=nonsense",
		"/api/alerts?order=sideways",
		"/api/alerts?severity=extreme",
		"/api/alerts?min_risk_score=high",
		"/api/alerts?anomaly=maybe",
		"/api/alerts?from_time=last-tuesday",
	}
	for _, url := range cases {
		rr := do(a, "GET", url)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("%s -> %d, want 400", url, rr.Code)
		}
	}
}

func TestGetAlert404(t *testing.T) {
	a, _ := newTestAPI(t, 200, `{"hits":{"total":{"value":0},"hits":[]}}`)
	rr := do(a, "GET", "/api/alerts/nope")
	if rr.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", rr.Code)
	}
}

func TestElasticsearchFailureIs502(t *testing.T) {
	a, _ := newTestAPI(t, 503, `{"error":"unavailable"}`)
	rr := do(a, "GET", "/api/alerts")
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("want 502, got %d (%s)", rr.Code, rr.Body.String())
	}
}

func TestStatsEndpointAndLegacyAlias(t *testing.T) {
	body := `{"hits":{"total":{"value":5}},"aggregations":{
	  "avg_risk":{"value":40},"max_risk":{"value":88},
	  "anomalies":{"doc_count":1},"last_24h":{"doc_count":2},
	  "by_severity":{"buckets":[{"key":"medium","doc_count":5}]}}}`
	a, _ := newTestAPI(t, 200, body)
	for _, path := range []string{"/api/alerts/stats", "/api/stats"} {
		rr := do(a, "GET", path)
		if rr.Code != 200 {
			t.Fatalf("%s -> %d", path, rr.Code)
		}
		var s elastic.Stats
		_ = json.Unmarshal(rr.Body.Bytes(), &s)
		if s.Total != 5 || s.MaxRiskScore != 88 {
			t.Fatalf("%s bad stats: %+v", path, s)
		}
	}
}

func TestRiskDistributionEndpoint(t *testing.T) {
	a, _ := newTestAPI(t, 200, `{"hits":{"total":{"value":3}},"aggregations":{"bands":{"buckets":[
	  {"key":"medium","doc_count":2},{"key":"critical","doc_count":1}]}}}`)
	rr := do(a, "GET", "/api/risk/distribution")
	if rr.Code != 200 {
		t.Fatalf("status %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "informational") {
		t.Fatalf("distribution missing zero-filled bands: %s", rr.Body.String())
	}
}

func TestMitreEndpointShape(t *testing.T) {
	a, _ := newTestAPI(t, 200, `{"hits":{"total":{"value":1}},"aggregations":{"techniques":{"buckets":[
	  {"key":"T1110","doc_count":9,"name":{"buckets":[{"key":"Brute Force","doc_count":9}]},
	   "tactic":{"buckets":[{"key":"Credential Access","doc_count":9}]},"max_conf":{"value":0.9}}]}}}`)
	rr := do(a, "GET", "/api/mitre/techniques")
	if rr.Code != 200 {
		t.Fatalf("status %d", rr.Code)
	}
	var out struct {
		Techniques []elastic.TechniqueCount `json:"techniques"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if len(out.Techniques) != 1 || out.Techniques[0].TechniqueID != "T1110" {
		t.Fatalf("bad mitre body: %s", rr.Body.String())
	}
}

func TestLegacyLogsEndpointStillWorks(t *testing.T) {
	a, _ := newTestAPI(t, 200, `{"hits":{"total":{"value":1},"hits":[
	  {"_id":"x","_source":{"event":{"type":"SYSCALL","timestamp":"2026-07-14T00:00:00Z"},
	   "host":{"name":"h1"},"risk":{"score":55,"severity":"medium"},
	   "detection":{"prediction":1,"model":"isolation_forest"},"process":{"command_line":"id"},"mitre":[]}}]}}`)
	rr := do(a, "GET", "/api/logs?sort_by=risk_score")
	if rr.Code != 200 {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	var out struct {
		Items []struct {
			RiskScore float64 `json:"risk_score"`
			AuditType string  `json:"audit_type"`
			Message   string  `json:"message"`
		} `json:"items"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if len(out.Items) != 1 || out.Items[0].RiskScore != 55 || out.Items[0].AuditType != "SYSCALL" {
		t.Fatalf("legacy body wrong: %s", rr.Body.String())
	}
}
