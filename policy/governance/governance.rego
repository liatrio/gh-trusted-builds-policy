package governance

import data.security

default allow = false

allow {
	pullrequest_violations
}

pullrequest_violations {
	some i
	attestation := json.unmarshal(input[i].Attestation)
	attestation.predicateType == "https://liatr.io/attestations/github-pull-request/v1"
	security.pullrequest.allow with input as attestation
}
