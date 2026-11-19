/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package policy

// Unit is an immutable platform evaluation bound to its policy reader. Platform
// adapters must bind the producer's failure from that same evaluation; consumers
// cannot substitute a separately inspected diagnostic list. Legitimate unknowns
// are reader facts, not producer failures. The engine preserves Failure even
// when it emits independently confirmed findings.
type Unit interface {
	Reader() Reader
	Failure() error
}
