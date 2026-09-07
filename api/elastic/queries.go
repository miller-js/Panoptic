package elastic

import (
	"context"
	"encoding/json"
	"time"
)

// --- raw Elasticsearch response shapes -------------------------------------

type searchHit struct {
	ID     string          `json:"_id"`
	Source json.RawMessage `json:"_source"`
}

func (h searchHit) toAlert() Alert {
	var a Alert
	_ = json.Unmarshal(h.Source, &a)
	a.ID = h.ID
	if a.Mitre == nil {
		a.Mitre = []MitreTag{}
	}
	if a.Risk.Factors == nil {
		a.Risk.Factors = []string{}
	}
	return a
}

type searchResponse struct {
	Hits struct {
		Total struct {
			Value int64 `json:"value"`
		} `json:"total"`
		Hits []searchHit `json:"hits"`
	} `json:"hits"`
	Aggregations json.RawMessage `json:"aggregations"`
}

// --- stats ----------------------------------------------------------------

type Stats struct {
	Total        int64            `json:"total"`
	AnomalyCount int64            `json:"anomaly_count"`
	AvgRiskScore float64          `json:"avg_risk_score"`
	MaxRiskScore float64          `json:"max_risk_score"`
	BySeverity   map[string]int64 `json:"by_severity"`
	Last24h      int64            `json:"last_24h"`
}

func (c *Client) AlertStats(ctx context.Context) (*Stats, error) {
	body := map[string]interface{}{
		"size":             0,
		"track_total_hits": true,
		"aggs": map[string]interface{}{
			"avg_risk": map[string]interface{}{"avg": map[string]interface{}{"field": "risk.score"}},
			"max_risk": map[string]interface{}{"max": map[string]interface{}{"field": "risk.score"}},
			"anomalies": map[string]interface{}{
				"filter": map[string]interface{}{"term": map[string]interface{}{"detection.prediction": -1}},
			},
			"by_severity": map[string]interface{}{
				"terms": map[string]interface{}{"field": "risk.severity", "size": 10},
			},
			"last_24h": map[string]interface{}{
				"filter": map[string]interface{}{"range": map[string]interface{}{"@timestamp": map[string]interface{}{"gte": "now-24h"}}},
			},
		},
	}
	res, err := c.search(ctx, body)
	if err != nil {
		return nil, err
	}

	var aggs struct {
		AvgRisk    metricAgg `json:"avg_risk"`
		MaxRisk    metricAgg `json:"max_risk"`
		Anomalies  docCount  `json:"anomalies"`
		Last24h    docCount  `json:"last_24h"`
		BySeverity termsAgg  `json:"by_severity"`
	}
	_ = json.Unmarshal(res.Aggregations, &aggs)

	bySev := map[string]int64{}
	for _, b := range aggs.BySeverity.Buckets {
		bySev[b.Key.(string)] = b.DocCount
	}
	return &Stats{
		Total:        res.Hits.Total.Value,
		AnomalyCount: aggs.Anomalies.DocCount,
		AvgRiskScore: round1(aggs.AvgRisk.Value),
		MaxRiskScore: aggs.MaxRisk.Value,
		BySeverity:   bySev,
		Last24h:      aggs.Last24h.DocCount,
	}, nil
}

// --- timeline (anomalies over time) --------------------------------------

type TimelineBucket struct {
	Timestamp string `json:"timestamp"`
	Total     int64  `json:"total"`
	Anomalies int64  `json:"anomalies"`
	High      int64  `json:"high_or_critical"`
}

type Timeline struct {
	Interval string           `json:"interval"`
	Buckets  []TimelineBucket `json:"buckets"`
}

func (c *Client) AnomalyTimeline(ctx context.Context, interval string, from, to *time.Time) (*Timeline, error) {
	if interval == "" {
		interval = "1h"
	}
	timeFilter := map[string]interface{}{}
	if from != nil {
		timeFilter["gte"] = from.UTC().Format(time.RFC3339)
	}
	if to != nil {
		timeFilter["lte"] = to.UTC().Format(time.RFC3339)
	}
	query := map[string]interface{}{"match_all": map[string]interface{}{}}
	if len(timeFilter) > 0 {
		query = map[string]interface{}{"bool": map[string]interface{}{"filter": []map[string]interface{}{
			{"range": map[string]interface{}{"event.timestamp": timeFilter}},
		}}}
	}
	body := map[string]interface{}{
		"size":  0,
		"query": query,
		"aggs": map[string]interface{}{
			"timeline": map[string]interface{}{
				"date_histogram": map[string]interface{}{
					"field":          "event.timestamp",
					"fixed_interval": interval,
					"min_doc_count":  0,
				},
				"aggs": map[string]interface{}{
					"anomalies": map[string]interface{}{"filter": map[string]interface{}{"term": map[string]interface{}{"detection.prediction": -1}}},
					"high":      map[string]interface{}{"filter": map[string]interface{}{"terms": map[string]interface{}{"risk.severity": []string{"high", "critical"}}}},
				},
			},
		},
	}
	res, err := c.search(ctx, body)
	if err != nil {
		return nil, err
	}
	var aggs struct {
		Timeline struct {
			Buckets []struct {
				KeyAsString string   `json:"key_as_string"`
				DocCount    int64    `json:"doc_count"`
				Anomalies   docCount `json:"anomalies"`
				High        docCount `json:"high"`
			} `json:"buckets"`
		} `json:"timeline"`
	}
	_ = json.Unmarshal(res.Aggregations, &aggs)

	out := &Timeline{Interval: interval, Buckets: make([]TimelineBucket, 0, len(aggs.Timeline.Buckets))}
	for _, b := range aggs.Timeline.Buckets {
		out.Buckets = append(out.Buckets, TimelineBucket{
			Timestamp: b.KeyAsString,
			Total:     b.DocCount,
			Anomalies: b.Anomalies.DocCount,
			High:      b.High.DocCount,
		})
	}
	return out, nil
}

// --- risk score distribution -------------------------------------------

type RiskBand struct {
	Key      string `json:"key"`
	Severity string `json:"severity"`
	From     int    `json:"from"`
	To       int    `json:"to"`
	Count    int64  `json:"count"`
}

type RiskDistribution struct {
	Total int64      `json:"total"`
	Bands []RiskBand `json:"bands"`
}

var riskBandDefs = []struct {
	sev      string
	from, to int
}{
	{"informational", 0, 20},
	{"low", 20, 40},
	{"medium", 40, 60},
	{"high", 60, 80},
	{"critical", 80, 101},
}

func (c *Client) RiskScoreDistribution(ctx context.Context) (*RiskDistribution, error) {
	ranges := make([]map[string]interface{}, 0, len(riskBandDefs))
	for _, d := range riskBandDefs {
		ranges = append(ranges, map[string]interface{}{"key": d.sev, "from": d.from, "to": d.to})
	}
	body := map[string]interface{}{
		"size":             0,
		"track_total_hits": true,
		"aggs": map[string]interface{}{
			"bands": map[string]interface{}{"range": map[string]interface{}{"field": "risk.score", "ranges": ranges}},
		},
	}
	res, err := c.search(ctx, body)
	if err != nil {
		return nil, err
	}
	var aggs struct {
		Bands struct {
			Buckets []struct {
				Key      string `json:"key"`
				DocCount int64  `json:"doc_count"`
			} `json:"buckets"`
		} `json:"bands"`
	}
	_ = json.Unmarshal(res.Aggregations, &aggs)

	counts := map[string]int64{}
	for _, b := range aggs.Bands.Buckets {
		counts[b.Key] = b.DocCount
	}
	out := &RiskDistribution{Total: res.Hits.Total.Value}
	for _, d := range riskBandDefs {
		out.Bands = append(out.Bands, RiskBand{
			Key:      bandLabel(d.sev, d.from, d.to),
			Severity: d.sev,
			From:     d.from,
			To:       d.to - 1,
			Count:    counts[d.sev],
		})
	}
	return out, nil
}

// --- MITRE technique overview ----------------------------------------

type TechniqueCount struct {
	TechniqueID   string  `json:"technique_id"`
	TechniqueName string  `json:"technique_name"`
	Tactic        string  `json:"tactic"`
	Count         int64   `json:"count"`
	MaxConfidence float64 `json:"max_confidence"`
}

func (c *Client) MitreTechniques(ctx context.Context, from, to *time.Time, size int) ([]TechniqueCount, error) {
	if size <= 0 {
		size = 20
	}
	query := map[string]interface{}{"exists": map[string]interface{}{"field": "mitre.technique_id"}}
	if from != nil || to != nil {
		r := map[string]interface{}{}
		if from != nil {
			r["gte"] = from.UTC().Format(time.RFC3339)
		}
		if to != nil {
			r["lte"] = to.UTC().Format(time.RFC3339)
		}
		query = map[string]interface{}{"bool": map[string]interface{}{"filter": []map[string]interface{}{
			{"exists": map[string]interface{}{"field": "mitre.technique_id"}},
			{"range": map[string]interface{}{"event.timestamp": r}},
		}}}
	}
	body := map[string]interface{}{
		"size":  0,
		"query": query,
		"aggs": map[string]interface{}{
			"techniques": map[string]interface{}{
				"terms": map[string]interface{}{"field": "mitre.technique_id", "size": size, "order": map[string]interface{}{"_count": "desc"}},
				"aggs": map[string]interface{}{
					"name":     map[string]interface{}{"terms": map[string]interface{}{"field": "mitre.technique_name", "size": 1}},
					"tactic":   map[string]interface{}{"terms": map[string]interface{}{"field": "mitre.tactic", "size": 1}},
					"max_conf": map[string]interface{}{"max": map[string]interface{}{"field": "mitre.confidence"}},
				},
			},
		},
	}
	res, err := c.search(ctx, body)
	if err != nil {
		return nil, err
	}
	var aggs struct {
		Techniques struct {
			Buckets []struct {
				Key      string    `json:"key"`
				DocCount int64     `json:"doc_count"`
				Name     termsAgg  `json:"name"`
				Tactic   termsAgg  `json:"tactic"`
				MaxConf  metricAgg `json:"max_conf"`
			} `json:"buckets"`
		} `json:"techniques"`
	}
	_ = json.Unmarshal(res.Aggregations, &aggs)

	out := make([]TechniqueCount, 0, len(aggs.Techniques.Buckets))
	for _, b := range aggs.Techniques.Buckets {
		out = append(out, TechniqueCount{
			TechniqueID:   b.Key,
			TechniqueName: firstKey(b.Name),
			Tactic:        firstKey(b.Tactic),
			Count:         b.DocCount,
			MaxConfidence: round2(b.MaxConf.Value),
		})
	}
	return out, nil
}

// --- shared agg decoding helpers -----------------------------------

type metricAgg struct {
	Value float64 `json:"value"`
}

type docCount struct {
	DocCount int64 `json:"doc_count"`
}

type termsAgg struct {
	Buckets []struct {
		Key      interface{} `json:"key"`
		DocCount int64       `json:"doc_count"`
	} `json:"buckets"`
}

func firstKey(t termsAgg) string {
	if len(t.Buckets) == 0 {
		return ""
	}
	if s, ok := t.Buckets[0].Key.(string); ok {
		return s
	}
	return ""
}

func bandLabel(sev string, from, to int) string {
	return itoa(from) + "-" + itoa(to-1) + " " + sev
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func round1(f float64) float64 { return float64(int64(f*10+0.5)) / 10 }
func round2(f float64) float64 { return float64(int64(f*100+0.5)) / 100 }
