// Package elastic wraps the Elasticsearch connection and the queries the API
// needs against the panoptic-predictions index.
package elastic

import (
	"os"

	"github.com/elastic/go-elasticsearch/v8"
)

// Client wraps the underlying Elasticsearch client with Panoptic-specific
// query methods.
type Client struct {
	es *elasticsearch.Client
}

// NewClient connects to Elasticsearch. Address/credentials match
// ml-service/elastic.py's hardcoded values by default — security is disabled
// on the cluster today, this is planned to change later.
func NewClient() (*Client, error) {
	addr := getenv("PANOPTIC_ES_ADDR", "http://192.168.10.100:9200")
	user := getenv("PANOPTIC_ES_USER", "elastic")
	pass := getenv("PANOPTIC_ES_PASSWORD", "changeme")

	es, err := elasticsearch.NewClient(elasticsearch.Config{
		Addresses: []string{addr},
		Username:  user,
		Password:  pass,
	})
	if err != nil {
		return nil, err
	}

	return &Client{es: es}, nil
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
