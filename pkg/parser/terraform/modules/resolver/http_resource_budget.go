/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"io"
	"net/http"
)

type resourceBudgetRoundTripper struct {
	base            http.RoundTripper
	fallbackMaximum int64
}

func (t *resourceBudgetRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := t.base.RoundTrip(request)
	if err != nil || response.Body == nil {
		return response, err
	}
	maximum := ResourceBudgetFromContext(request.Context()).Limits().MaxPackageBytes
	if t.fallbackMaximum > 0 && (maximum <= 0 || t.fallbackMaximum < maximum) {
		maximum = t.fallbackMaximum
	}
	if maximum > 0 {
		response.Body = &resourceBudgetBody{
			ReadCloser: response.Body,
			maximum:    maximum,
		}
	}
	return response, nil
}

type resourceBudgetBody struct {
	io.ReadCloser
	maximum int64
	read    int64
}

func (r *resourceBudgetBody) Read(buffer []byte) (int, error) {
	remaining := r.maximum - r.read
	if remaining > 0 {
		if int64(len(buffer)) > remaining {
			buffer = buffer[:remaining]
		}
		n, err := r.ReadCloser.Read(buffer)
		r.read += int64(n)
		return n, err
	}
	var probe [1]byte
	n, err := r.ReadCloser.Read(probe[:])
	if n > 0 {
		return 0, &BudgetExceededError{
			Gate:     "stream",
			Limit:    limitPackageBytes,
			Maximum:  r.maximum,
			Measured: r.read + int64(n),
		}
	}
	return 0, err
}

func withResourceBudgetTransport(client *http.Client, fallbackMaximum int64) *http.Client {
	if client == nil {
		return nil
	}
	if existing, ok := client.Transport.(*resourceBudgetRoundTripper); ok {
		existing.fallbackMaximum = fallbackMaximum
		return client
	}
	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	cloned := *client
	cloned.Transport = &resourceBudgetRoundTripper{base: transport, fallbackMaximum: fallbackMaximum}
	return &cloned
}
