package security.pullrequest

default allow = false

allow {
	print(violation)
	count(violation) == 0
}

violation[msg] {
	input.predicate.reviewers == null
	msg := "pull request reviewers is null"
}

violation[msg] {
	count(input.predicate.reviewers) < 1
	msg := "pull request reviewers is less than 1"
}
