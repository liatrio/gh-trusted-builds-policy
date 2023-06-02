package governance
import data.security

default allow = false
identities := [{
	"issuer": "https://token.actions.githubusercontent.com",
    "subject": "https://github.com/liatrio/gh-trusted-builds-workflows/.github/workflows/build-and-push.yaml@refs/heads/main"
},
{
	"issuer": "https://token.actions.githubusercontent.com",
    "subject": "https://github.com/liatrio/gh-trusted-builds-workflows/.github/workflows/scan-image.yaml@refs/heads/main"
}]

attestations := verify_image_attestations(input.image, identities)

pullrequest_attestations :=
    [att | json.unmarshal(attestations[i].Attestation).predicateType == "https://liatr.io/attestations/github-pull-request/v1"; att := json.unmarshal(attestations[i].Attestation)]

trivy_attestations :=
    [att | json.unmarshal(attestations[i].Attestation).predicateType == "https://cosign.sigstore.dev/attestation/vuln/v1"; att := json.unmarshal(attestations[i].Attestation)]

sbom_attestations :=
    [att | json.unmarshal(attestations[i].Attestation).predicateType == "https://spdx.dev/Document"; att := json.unmarshal(attestations[i].Attestation)]

result := {
    "allow": allow,
    "attestations": attestations
}

allow {
    violations := pullrequest_violations | trivy_violations | sbom_violations
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

sbom_violations[msg] {
    count(sbom_attestations) == 0
    msg:= "no sbom attestation"
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
