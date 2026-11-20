/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package model

// Why a file the scan found gave no documents to scan, as the parse log
// classes it. Exporters such as the inventory report these values.
const (
	ParseFailureParseError       = "parse_error"
	ParseFailureHelmRenderFailed = "helm_render_failed"
	ParseFailureTestFixture      = "test_fixture"
	ParseFailureTemplateSyntax   = "template_syntax"
	// ParseFailureTooLarge marks a file skipped for its size.
	ParseFailureTooLarge = "too_large"
	// ParseFailureUnknown marks a file that gave no documents for no
	// recorded reason.
	ParseFailureUnknown = "unknown"
)
