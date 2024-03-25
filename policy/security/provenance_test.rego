package security.provenance

# Test that allow is false when buildType is incorrect
test_fail_incorrect_buildType {
	input := {"predicate": {"buildType": "incorrect_buildType", "invocation": {"environment": {"github_event_payload": {"enterprise": {"name": "Liatrio"}}}}}}
	not allow with input as input
}

# Test that allow is false when enterprise name is not Liatrio
test_fail_incorrect_enterprise_name {
	input := {"predicate": {"buildType": "https://github.com/slsa-framework/slsa-github-generator/container@v1", "invocation": {"environment": {"github_event_payload": {"enterprise": {"name": "NotLiatrio"}}}}}}
	not allow with input as input
}

# Test that allow is true when buildType is correct and enterprise name is Liatrio
test_allow_correct_buildType_and_enterprise_name {
	input := {"predicate": {"buildType": "https://github.com/slsa-framework/slsa-github-generator/container@v1", "invocation": {"environment": {"github_event_payload": {"enterprise": {"name": "Liatrio"}}}}}}
	allow with input as input
}

# Test that violation message is correct when buildType is incorrect
test_violation_incorrect_buildType {
	input := {"predicate": {"buildType": "incorrect_buildType", "invocation": {"environment": {"github_event_payload": {"enterprise": {"name": "Liatrio"}}}}}}
	violation[msg] with input as input
	msg == "provenance build type is incorrect"
}

# Test that violation message is correct when enterprise name is not Liatrio
test_violation_incorrect_enterprise_name {
	input := {"predicate": {"buildType": "https://github.com/slsa-framework/slsa-github-generator/container@v1", "invocation": {"environment": {"github_event_payload": {"enterprise": {"name": "NotLiatrio"}}}}}}
	violation[msg] with input as input
	msg == "provenance enterprise name is not Liatrio"
}
