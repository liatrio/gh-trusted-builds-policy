package governance

import data.security

default allow = false

pullrequest_attestations := [att | json.unmarshal(input[i].Attestation).predicateType == "https://liatr.io/attestations/github-pull-request/v1"; att := json.unmarshal(input[i].Attestation)]

trivy_attestations := [att | json.unmarshal(input[i].Attestation).predicateType == "https://cosign.sigstore.dev/attestation/vuln/v1"; att := json.unmarshal(input[i].Attestation)]

sbom_attestations := [att | json.unmarshal(input[i].Attestation).predicateType == "https://spdx.dev/Document"; att := json.unmarshal(input[i].Attestation)]

provenance_attestations := [att | json.unmarshal(input[i].Attestation).predicateType == "https://slsa.dev/provenance/v0.2"; att := json.unmarshal(input[i].Attestation)]

allow {
	violations := ((pullrequest_violations | trivy_violations) | sbom_violations) | provenance_violations
	print(violations)
	count(violations) == 0
}

provenance_violations[msg] {
	count(provenance_attestations) == 0
	msg := "no provenance attestation"
}

provenance_violations[msg] {
	some i
	attestation := provenance_attestations[i]
	not security.provenance.allow with input as attestation
	msg := "provenance violation found"
}

pullrequest_violations[msg] {
	count(pullrequest_attestations) == 0
	msg := "no pull request attestation"
}

pullrequest_violations[msg] {
	not security.pullrequest.allow with input as pullrequest_attestations[0]
	msg := "pull request violations found"
}

sbom_violations[msg] {
	count(sbom_attestations) == 0
	msg := "no sbom attestation"
}

trivy_violations[msg] {
	count(trivy_attestations) == 0
	msg := "no trivy attestation"
}

trivy_violations[msg] {
	some i
	attestation := trivy_attestations[i]
	not security.trivy.allow with input as attestation
	msg := "trivy scan violation found"
}
