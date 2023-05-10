package governance
import data.security

default allow = false

pullrequest_attestations :=
    [att | json.unmarshal(input[i].Attestation).predicateType == "https://liatr.io/attestations/github-pull-request/v1"; att := json.unmarshal(input[i].Attestation)]

trivy_attestations :=
    [att | json.unmarshal(input[i].Attestation).predicateType == "https://cosign.sigstore.dev/attestation/vuln/v1"; att := json.unmarshal(input[i].Attestation)]


allow {
    violations := pullrequest_violations | trivy_violations
    print(violations)
    count(violations) == 0
}

pullrequest_violations[msg] {
    count(pullrequest_attestations) == 0
    msg := "no pull request attestation"
}

pullrequest_violations[msg] {
	not security.pullrequest.allow with input as pullrequest_attestations[0]
	msg := "pull request violations found"
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
