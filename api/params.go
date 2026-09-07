package main

import (
	"net/url"
	"strconv"
	"strings"
	"time"
)

// paramError is returned by the parse helpers and mapped to a 400 by callers.
type paramError struct{ msg string }

func (e *paramError) Error() string { return e.msg }

func badParam(msg string) error { return &paramError{msg} }

func parseSize(q url.Values, def, max int) (int, error) {
	v := q.Get("size")
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		return 0, badParam("size must be a positive integer")
	}
	if n > max {
		n = max
	}
	return n, nil
}

func parseFrom(q url.Values) (int, error) {
	v := q.Get("from")
	if v == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0, badParam("from must be a non-negative integer")
	}
	return n, nil
}

func parseFloatPtr(q url.Values, key string) (*float64, error) {
	v := q.Get(key)
	if v == "" {
		return nil, nil
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return nil, badParam(key + " must be a number")
	}
	return &f, nil
}

func parseBool(q url.Values, key string) (bool, error) {
	v := q.Get(key)
	if v == "" {
		return false, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, badParam(key + " must be true or false")
	}
	return b, nil
}

func parseEnum(q url.Values, key string, allowed ...string) (string, error) {
	v := q.Get(key)
	if v == "" {
		return "", nil
	}
	for _, a := range allowed {
		if v == a {
			return v, nil
		}
	}
	return "", badParam(key + " must be one of: " + strings.Join(allowed, ", "))
}

var validSeverities = map[string]bool{
	"informational": true, "low": true, "medium": true, "high": true, "critical": true,
}

func parseSeverities(q url.Values) ([]string, error) {
	raw := q.Get("severity")
	if raw == "" {
		return nil, nil
	}
	var out []string
	for _, s := range strings.Split(raw, ",") {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" {
			continue
		}
		if !validSeverities[s] {
			return nil, badParam("severity must be a comma list of: informational, low, medium, high, critical")
		}
		out = append(out, s)
	}
	return out, nil
}

func parseTimePtr(q url.Values, key string) (*time.Time, error) {
	v := q.Get(key)
	if v == "" {
		return nil, nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, v); err == nil {
			return &t, nil
		}
	}
	return nil, badParam(key + " must be an RFC3339 timestamp or YYYY-MM-DD date")
}
