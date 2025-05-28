jira_issue_status=$(curl -s "${BASE_URL}/rest/api/3/issue/${JIRA_ISSUE_ID}?fields=status" --user "${USER_EMAIL}":"${API_TOKEN}" | jq .fields.status.name)
