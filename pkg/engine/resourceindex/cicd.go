/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resourceindex

import "fmt"

func indexCICDDoc(index, doc map[string]interface{}, docID string) {
	resourceName, _ := doc["name"].(string)
	if resourceName == "" {
		resourceName = "workflow"
	}

	workflowEntry := makeCICDEntry(publicDocumentAttrs(doc), docID, GitHubActionBucket, resourceName, ddPath())
	setEvalScope(workflowEntry, "workflow", docID)
	addEntry(index, GitHubActionBucket, resourceName, workflowEntry)

	workflowContext := selectedAttrs(doc, "name", "on", "permissions", "env", "defaults")
	if jobs, ok := asMap(doc["jobs"]); ok {
		for jobID, rawJob := range jobs {
			if isInternalKey(jobID) {
				continue
			}
			job, ok := asMap(rawJob)
			if !ok {
				continue
			}
			jobPath := ddPath("jobs", jobID)
			jobScope := docID + ":job:" + jobID

			jobEntry := makeCICDEntry(job, docID, GitHubJobBucket, jobID, jobPath)
			jobEntry["workflow"] = workflowContext
			setEvalScope(jobEntry, "workflow", docID)
			setRelScope(jobEntry, "job", jobScope)
			addEntry(index, GitHubJobBucket, jobID, jobEntry)

			jobContext := selectedAttrs(job, "name", "permissions", "env", "defaults", "runs-on")
			indexGitHubServices(index, job["services"], docID, resourceName, jobID,
				appendPath(jobPath, "services"), workflowContext, jobContext, docID, jobScope)
			indexGitHubSteps(index, job["steps"], docID, resourceName, jobID,
				appendPath(jobPath, "steps"), workflowContext, jobContext, docID, jobScope)
		}
	}

	if runs, ok := asMap(doc["runs"]); ok {
		runsScope := docID + ":job:runs"
		indexGitHubSteps(index, runs["steps"], docID, resourceName, "runs",
			ddPath("runs", "steps"), workflowContext, selectedAttrs(runs, "using"), docID, runsScope)
	}

	indexDependabotUpdates(index, doc["updates"], docID)
}

func indexGitHubSteps(
	index map[string]interface{},
	rawSteps interface{},
	docID, workflowName, jobID string,
	basePath []interface{},
	workflowContext, jobContext map[string]interface{},
	workflowScope, jobScope string,
) {
	steps, ok := rawSteps.([]interface{})
	if !ok {
		return
	}
	for idx, rawStep := range steps {
		step, ok := asMap(rawStep)
		if !ok {
			continue
		}
		stepName := firstNonEmptyString(step, "name", "id")
		if stepName == "" {
			stepName = fmt.Sprintf("%s/step:%d", jobID, idx)
		}
		entry := makeCICDEntry(step, docID, GitHubStepBucket, stepName, appendPath(basePath, idx))
		entry["workflow"] = workflowContext
		entry["job"] = jobContext
		entry["jobId"] = jobID
		entry["workflowName"] = workflowName
		setEvalScope(entry, "workflow", workflowScope)
		setRelScope(entry, "job", jobScope)
		addEntry(index, GitHubStepBucket, stepName, entry)
	}
}

func indexGitHubServices(
	index map[string]interface{},
	rawServices interface{},
	docID, workflowName, jobID string,
	basePath []interface{},
	workflowContext, jobContext map[string]interface{},
	workflowScope, jobScope string,
) {
	services, ok := asMap(rawServices)
	if !ok {
		return
	}
	for serviceName, rawService := range services {
		if isInternalKey(serviceName) {
			continue
		}
		service, ok := asMap(rawService)
		if !ok {
			continue
		}
		entry := makeCICDEntry(service, docID, GitHubServiceBucket, serviceName, appendPath(basePath, serviceName))
		entry["workflow"] = workflowContext
		entry["job"] = jobContext
		entry["jobId"] = jobID
		entry["workflowName"] = workflowName
		setEvalScope(entry, "workflow", workflowScope)
		setRelScope(entry, "job", jobScope)
		addEntry(index, GitHubServiceBucket, serviceName, entry)
	}
}

func indexDependabotUpdates(index map[string]interface{}, rawUpdates interface{}, docID string) {
	updates, ok := rawUpdates.([]interface{})
	if !ok {
		return
	}
	for idx, rawUpdate := range updates {
		update, ok := asMap(rawUpdate)
		if !ok {
			continue
		}
		resourceName := ""
		ecosystem := firstNonEmptyString(update, "package-ecosystem")
		directory := firstNonEmptyString(update, "directory")
		if ecosystem != "" && directory != "" {
			resourceName = ecosystem + ":" + directory
		}
		if resourceName == "" {
			resourceName = fmt.Sprintf("update:%d", idx)
		}
		entry := makeCICDEntry(update, docID, DependabotUpdateBucket, resourceName, ddPath("updates", idx))
		setEvalScope(entry, "workflow", docID)
		addEntry(index, DependabotUpdateBucket, resourceName, entry)
	}
}
