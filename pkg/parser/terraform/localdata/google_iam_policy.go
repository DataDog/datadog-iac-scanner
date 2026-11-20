/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package localdata

import (
	"bytes"
	"encoding/json"
)

// googleIAMPolicyType is the Google data source that renders an IAM policy.
const googleIAMPolicyType = "google_iam_policy"

type googlePolicy struct {
	AuditConfigs []googleAuditConfig `json:"auditConfigs,omitempty"`
	Bindings     []googleBinding     `json:"bindings,omitempty"`
}

type googleBinding struct {
	Condition *googleCondition `json:"condition,omitempty"`
	Members   []string         `json:"members,omitempty"`
	Role      string           `json:"role,omitempty"`
}

type googleCondition struct {
	Description string `json:"description,omitempty"`
	Expression  string `json:"expression,omitempty"`
	Title       string `json:"title,omitempty"`
}

type googleAuditConfig struct {
	AuditLogConfigs []googleAuditLogConfig `json:"auditLogConfigs,omitempty"`
	Service         string                 `json:"service,omitempty"`
}

type googleAuditLogConfig struct {
	ExemptedMembers []string `json:"exemptedMembers,omitempty"`
	LogType         string   `json:"logType,omitempty"`
}

// googleIAMPolicyAttributes renders policy_data in the JSON shape of a GCP IAM
// policy, as Terraform does.
func googleIAMPolicyAttributes(d decoder, input Configuration) map[string]string {
	var policy googlePolicy
	for _, block := range d.blocks(input, "binding") {
		policy.Bindings = append(policy.Bindings, d.googleBinding(block))
	}
	for _, block := range d.blocks(input, "audit_config") {
		policy.AuditConfigs = append(policy.AuditConfigs, d.googleAuditConfig(block))
	}
	if d.ctx.Err() != nil || d.state.documentIncomplete ||
		(!d.document && (d.state.unresolved || len(d.state.diagnostics) > 0)) {
		return nil
	}
	buf := &bytes.Buffer{}
	encoder := json.NewEncoder(buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(policy); err != nil {
		d.invalid(input, "policy_data", "could not be encoded")
		return nil
	}
	return map[string]string{"policy_data": string(bytes.TrimSuffix(buf.Bytes(), []byte("\n")))}
}
func (d decoder) googleBinding(input Configuration) googleBinding {
	binding := googleBinding{Role: d.str(input, "role"), Members: d.list(input, "members")}
	conditions := d.blocks(input, "condition")
	if len(conditions) > 1 {
		d.invalid(input, "condition", "allows at most one block")
	}
	for i, block := range conditions {
		condition := &googleCondition{
			Description: d.str(block, "description"), Expression: d.str(block, "expression"), Title: d.str(block, "title"),
		}
		// Retain legacy first-condition rendering while checking all consumed
		// known siblings. Failed native configurations never expose this JSON.
		if i == 0 {
			binding.Condition = condition
		}
	}

	return binding
}
func (d decoder) googleAuditConfig(input Configuration) googleAuditConfig {
	config := googleAuditConfig{Service: d.str(input, "service")}
	for _, block := range d.blocks(input, "audit_log_configs") {
		config.AuditLogConfigs = append(config.AuditLogConfigs, googleAuditLogConfig{
			ExemptedMembers: d.list(block, "exempted_members"), LogType: d.str(block, "log_type"),
		})
	}
	return config
}
