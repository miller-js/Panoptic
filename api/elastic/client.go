// Package elastic wraps the Elasticsearch connection and the queries the API
// needs against the panoptic-alerts index (written by ml-service).
//
// Layering: this package only builds query bodies and decodes responses. HTTP
// concerns live in the handlers; alerting/scoring logic lives in ml-service.
package elastic

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/elastic/go-elasticsearch/v8"
)

// Client wraps the underlying Elasticsearch client with Panoptic-specific
// query methods.
type Client struct {
	es          *elasticsearch.Client
	alertsIndex string
}

// Config controls how the client connects. Zero values fall back to env vars
// then to the ml-service defaults.
type Config struct {
	Addresses   []string
	Username    string
	Password    string
	AlertsIndex string
	// Transport, when set, overrides the HTTP round-tripper -- used by tests to
	// serve canned Elasticsearch responses without a real cluster.
	Transport http.RoundTripper
}

// NewClient connects using environment configuration.
//
//	PANOPTIC_ES_ADDR      default http://192.168.10.100:9200 (matches ml-service)
//	PANOPTIC_ES_USER      default elastic   (cluster security is disabled today)
//	PANOPTIC_ES_PASSWORD  default changeme
//	PANOPTIC_ALERTS_INDEX default panoptic-alerts
func NewClient() (*Client, error) {
	return NewClientWithConfig(Config{})
}

func NewClientWithConfig(cfg Config) (*Client, error) {
	if len(cfg.Addresses) == 0 {
		cfg.Addresses = []string{getenv("PANOPTIC_ES_ADDR", "http://192.168.10.100:9200")}
	}
	if cfg.Username == "" {
		cfg.Username = getenv("PANOPTIC_ES_USER", "elastic")
	}
	if cfg.Password == "" {
		cfg.Password = getenv("PANOPTIC_ES_PASSWORD", "changeme")
	}
	if cfg.AlertsIndex == "" {
		cfg.AlertsIndex = getenv("PANOPTIC_ALERTS_INDEX", "panoptic-alerts")
	}

	es, err := elasticsearch.NewClient(elasticsearch.Config{
		Addresses: cfg.Addresses,
		Username:  cfg.Username,
		Password:  cfg.Password,
		Transport: cfg.Transport,
	})
	if err != nil {
		return nil, err
	}
	return &Client{es: es, alertsIndex: cfg.AlertsIndex}, nil
}

// AlertsIndex is the index this client reads alerts from.
func (c *Client) AlertsIndex() string { return c.alertsIndex }

// ErrNotFound is returned by Get when no document matches the given ID.
var ErrNotFound = fmt.Errorf("not found")

func (c *Client) search(ctx context.Context, body map[string]interface{}) (*searchResponse, error) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(body); err != nil {
		return nil, err
	}

	res, err := c.es.Search(
		c.es.Search.WithContext(ctx),
		c.es.Search.WithIndex(c.alertsIndex),
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

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
