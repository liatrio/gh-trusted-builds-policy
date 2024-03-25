package governance_test

import data.governance.allow

test_all_pass {
	case := [data.test.pullrequest.two_reviewers, data.test.trivy.no_results, data.test.sbom.app, data.test.provenance]
	allow with input as case
}

test_fail_no_pull_request {
	case := [data.test.trivy.no_results]
	not allow with input as case
}

test_fail_no_reviewer {
	case := [data.test.pullrequest.no_reviewer, data.test.trivy.no_results]
	not allow with input as case
}

test_fail_null_reviewer {
	case := [data.test.pullrequest.null_reviewer, data.test.trivy.no_results]
	not allow with input as case
}

test_fail_medium_vuln {
	case := [data.test.pullrequest.two_reviewers, data.test.trivy.medium_pkg_result]
	not allow with input as case
}

test_fail_no_sbom {
	case := [data.test.pullrequest.two_reviewers, data.test.trivy.no_results]
	not allow with input as case
}
