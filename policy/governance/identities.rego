package governance

signer_identities := [
	{
		"issuer": "https://token.actions.githubusercontent.com",
		"subjectRegExp": `^https://github\.com/liatrio/.*/\.github/workflows/build-and-push\.yaml@refs/tags/v\d+\.\d+\.\d+$`,
	},
	{
		"issuer": "https://token.actions.githubusercontent.com",
		"subjectRegExp": `^https://github\.com/liatrio/.*/\.github/workflows/scan-image\.yaml@refs/tags/v\d+\.\d+\.\d+$`,
	},
]
