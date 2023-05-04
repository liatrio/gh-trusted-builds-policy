package security.trivy

default allow = false

allow {
    print(violation)
    count(violation) == 0
}

violation[msg] {
    severities := ["MEDIUM","HIGH","CRITICAL"]
    input.predicate.scanner.result.Results[_].Vulnerabilities[_].Severity == severities[_]
    msg := "vulnerability higher than medium"
}