package security.provenance

default allow = false

allow {
	count(violation) == 0
}

buildType := "https://github.com/slsa-framework/slsa-github-generator/container@v1"

orgName := "Liatrio"

violation[msg] {
	input.predicate.buildType != buildType
	msg := "provenance build type is incorrect"
}

violation[msg] {
	input.predicate.invocation.environment.github_event_payload.enterprise.name != orgName
	msg := "provenance enterprise name is not Liatrio"
}
