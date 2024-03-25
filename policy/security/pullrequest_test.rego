package security.pullrequest

# Test that allow is false when there are no reviewers
test_allow_no_reviewers {
	input := {"predicate": {"reviewers": null}}
	not allow with input as input
}

# Test that allow is false when reviewers count is less than 1
test_allow_less_than_one_reviewer {
	input := {"predicate": {"reviewers": []}}
	not allow with input as input
}

# Test that allow is true when reviewers count is 1 or more
test_allow_one_or_more_reviewers {
	input := {"predicate": {"reviewers": ["Alice"]}}
	allow with input as input
}

# Test that violation message is correct when there are no reviewers
test_violation_no_reviewers {
	input := {"predicate": {"reviewers": null}}
	violation[msg] with input as input
	msg == "pull request reviewers is null"
}

# Test that violation message is correct when reviewers count is less than 1
test_violation_less_than_one_reviewer {
	input := {"predicate": {"reviewers": []}}
	violation[msg] with input as input
	msg == "pull request reviewers is less than 1"
}
