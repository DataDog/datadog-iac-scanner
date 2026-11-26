/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2026 Datadog, Inc.
 */
package resolver

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// archiveRetryAfterTransport belongs to one getter attempt. It observes the
// delay before go-getter converts the failed response to a status-only error.
type archiveRetryAfterTransport struct {
	base  http.RoundTripper
	delay time.Duration
}

func (t *archiveRetryAfterTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	response, err := t.base.RoundTrip(req)
	// The getter may ignore a failed HEAD and then download the archive with GET.
	if req.Method == http.MethodGet {
		t.delay = 0
		if err == nil && (response.StatusCode == http.StatusTooManyRequests || response.StatusCode == http.StatusServiceUnavailable) {
			t.delay = archiveRetryAfterDelay(response.Header.Get("Retry-After"), time.Now())
		}
	}
	return response, err
}

func archiveRetryAfterDelay(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if value != "" && strings.Trim(value, "0123456789") == "" {
		// ParseInt returns the largest value on overflow, which can also be capped.
		seconds, _ := strconv.ParseInt(value, 10, 64)
		return time.Duration(min(seconds, int64(fetchRetryMaxDelay/time.Second))) * time.Second
	}
	if date, err := http.ParseTime(value); err == nil {
		return date.Sub(now)
	}
	return 0
}
