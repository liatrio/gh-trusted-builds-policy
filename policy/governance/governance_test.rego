package governance_test

import data.governance.allow

test_all_pass {
	case := [data.test.pullrequest.two_reviewers]
	print(case)
	allow with input as case
}

test_fail_no_reviewer {
	case := [data.test.pullrequest.no_reviewer]
	print(case)
	not allow with input as case
}
