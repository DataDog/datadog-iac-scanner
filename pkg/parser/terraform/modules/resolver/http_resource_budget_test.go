/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

type budgetRoundTripFunc func(*http.Request) (*http.Response, error)

func (f budgetRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestResourceBudgetBodyStopsBeforeReturningExcessByte(t *testing.T) {
	t.Parallel()

	body := &resourceBudgetBody{
		ReadCloser: io.NopCloser(bytes.NewReader([]byte("1234"))),
		maximum:    3,
	}
	buffer := make([]byte, 8)

	n, err := body.Read(buffer)
	require.NoError(t, err)
	require.Equal(t, 3, n)
	require.Equal(t, "123", string(buffer[:n]))

	n, err = body.Read(buffer)
	require.Zero(t, n)
	var budgetErr *BudgetExceededError
	require.True(t, errors.As(err, &budgetErr))
	require.Equal(t, int64(4), budgetErr.Measured)
}

func TestResourceBudgetTransportUsesStandaloneLimit(t *testing.T) {
	t.Parallel()

	transport := &resourceBudgetRoundTripper{
		base: budgetRoundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader([]byte("1234"))),
			}, nil
		}),
		fallbackMaximum: 3,
	}
	ctx := WithResourceBudget(t.Context(), NewResourceBudget(ResourceLimits{MaxPackageBytes: 10}))
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com", nil)
	require.NoError(t, err)
	response, err := transport.RoundTrip(request)
	require.NoError(t, err)

	_, err = io.ReadAll(response.Body)

	var budgetErr *BudgetExceededError
	require.True(t, errors.As(err, &budgetErr))
	require.Equal(t, int64(3), budgetErr.Maximum)
}
