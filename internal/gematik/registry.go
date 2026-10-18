package gematik

import "sekidp-ctk/internal/suite"

// Registry returns the gemSpec_IDP_Sek test catalog in execution order:
// statements and infrastructure first (no login needed), then PAR, the
// authorization endpoint and the token endpoint.
func Registry() *suite.Registry {
	r := &suite.Registry{}
	r.Add(entityStatementTests()...)
	r.Add(federationTests()...)
	r.Add(infraTests()...)
	r.Add(parTests()...)
	r.Add(inputTests()...)
	r.Add(authzTests()...)
	r.Add(tokenTests()...)
	return r
}
