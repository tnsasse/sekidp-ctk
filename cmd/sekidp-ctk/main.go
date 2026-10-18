// Command sekidp-ctk tests a sector identity provider (sektoraler IDP) of
// the gematik TI federation against gemSpec_IDP_Sek.
package main

import (
	"sekidp-ctk/internal/cli"
	"sekidp-ctk/internal/gematik"
	"sekidp-ctk/internal/suite"
)

func main() {
	cli.Tool{
		Name:        "sekidp-ctk",
		Description: "conformance test kit for gematik sector identity providers (gemSpec_IDP_Sek 3.3.0)",
		ReportTitle: "gemSpec_IDP_Sek conformance report",
		SpecHelp:    "gemSpec_IDP_Sek",
		Registry:    gematik.Registry,
		Load:        load,
	}.Main()
}

func load(path string) (string, *suite.Env, error) {
	cfg, err := gematik.Load(path)
	if err != nil {
		return "", nil, err
	}
	name := cfg.IDP.Name
	if name == "" {
		name = cfg.IDP.EntityID
	}
	return name, &suite.Env{Data: cfg, Transport: gematik.NewTransport(cfg)}, nil
}
