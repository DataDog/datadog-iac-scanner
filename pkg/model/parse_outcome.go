/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package model

// Parse diagnostics classify unavailable coverage. Some retain usable documents,
// such as the unconditional branch of an undecidable include. Exporters and
// completeness accounting use these values.
const (
	ParseFailureParseError        = "parse_error"
	ParseFailureResourceLimit     = "resource_limit"
	ParseFailureInvalidInclude    = "invalid_include"
	ParseFailureInvalidPipeline   = "invalid_pipeline"
	ParseFailureUnresolvedInclude = "unresolved_include"
	ParseFailureHelmRenderFailed  = "helm_render_failed"
	ParseFailureTestFixture       = "test_fixture"
	ParseFailureTemplateSyntax    = "template_syntax"
	// ParseFailureTooLarge marks a file skipped for its size.
	ParseFailureTooLarge = "too_large"
	// ParseFailureUnknown marks a file that gave no documents for no
	// recorded reason.
	ParseFailureUnknown = "unknown"
)
