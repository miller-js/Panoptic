package elastic

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
)

// fakeES is an http.RoundTripper that records the last request body and
// replies with a canned Elasticsearch response, so the query layer can be
// tested without a cluster.
type fakeES struct {
	status   int
	response string
	lastBody map[string]interface{}
	lastPath string
	calls    int
}

func (f *fakeES) RoundTrip(req *http.Request) (*http.Response, error) {
	f.calls++
	f.lastPath = req.URL.Path
	if req.Body != nil {
		raw, _ := io.ReadAll(req.Body)
		f.lastBody = map[string]interface{}{}
		_ = json.Unmarshal(raw, &f.lastBody)
	}
	status := f.status
	if status == 0 {
		status = 200
	}
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     http.Header{"Content-Type": []string{"application/json"}, "X-Elastic-Product": []string{"Elasticsearch"}},
		Body:       io.NopCloser(bytes.NewBufferString(f.response)),
		Request:    req,
	}, nil
}

func newTestClient(t interface {
	Fatalf(string, ...interface{})
}, fake *fakeES) *Client {
	c, err := NewClientWithConfig(Config{
		Addresses: []string{"http://es.test:9200"},
		Transport: fake,
	})
	if err != nil {
		t.Fatalf("NewClientWithConfig: %v", err)
	}
	return c
}

// nestedString walks a decoded JSON map by keys and returns the string it finds.
func nestedString(m map[string]interface{}, keys ...string) (string, bool) {
	var cur interface{} = m
	for _, k := range keys {
		mm, ok := cur.(map[string]interface{})
		if !ok {
			return "", false
		}
		cur = mm[k]
	}
	s, ok := cur.(string)
	return s, ok
}

func nestedAny(m map[string]interface{}, keys ...string) (interface{}, bool) {
	var cur interface{} = m
	for _, k := range keys {
		mm, ok := cur.(map[string]interface{})
		if !ok {
			return nil, false
		}
		cur = mm[k]
	}
	return cur, cur != nil
}
