# gh-trusted-builds-policy

Open Policy Agent bundle for automated governance.

Bundles are made available as GitHub releases.

## Packages

### `governance`

Designed for use by automated governance trusted workflows.
Encapsulates verifying all rules required for governance approval, 
and handling input transformation.
Input is expected to be a json list of all Rekor transparency log entries for a given artifact.

#### Rules

- `data.governance.allow`: Returns `true` if no violations are found across all governance rules. 

### `security`

Core rules related to security policies.
Contains multiple packages for different topics.

#### Rules

- `data.security.pullrequest.allow`: Returns `true` if no violations are found for a given pull request.
Input is expected to be a single [Liatrio GitHub pull request attestation](https://github.com/liatrio/custom-attestations-poc#github-pull-request).

## Release

A new bundle will be published on every push to `main`.
Semantic commits are used to automate the semver process.

## Test

The [test/](test) directory contains example inputs for testing.
Each package has its own json file for related inputs.
The json file has a single, top level property that matches the package name.
This is to avoid collisions, with how opa loads all data for tests.

Policy test files live alongside the policy they are testing, as `*_test.rego`.

### Commands

- `opa test .`: Run all automated policy tests.
- `opa test -v .`: See test case inputs, and violations.
Useful for troubleshooting.