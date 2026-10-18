// Package gematik tests a sector identity provider (sektoraler IDP) of the
// gematik TI federation against gemSpec_IDP_Sek. The test kit acts as a
// Fachdienst (relying party) of the federation: it authenticates with mTLS
// (self_signed_tls_client_auth), uses PAR, PKCE and decrypts the ID token.
package gematik

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"

	"sekidp-ctk/internal/useragent"
	"sekidp-ctk/internal/yamlenv"
)

type Config struct {
	IDP              IDP               `yaml:"idp"`
	FederationMaster *FederationMaster `yaml:"federation_master"`
	// Fachdienst is the test relying party registered in the federation. PAR,
	// authorization and token checks need it.
	Fachdienst *Fachdienst `yaml:"fachdienst"`
	// FachdienstB is a second registered relying party, used to check that
	// the pairwise subject differs between Fachdienste (A_23197-01).
	FachdienstB *Fachdienst      `yaml:"fachdienst_b"`
	Login       Login            `yaml:"login"`
	TLS         TLS              `yaml:"tls"`
	Timeout     yamlenv.Duration `yaml:"timeout"`
}

type IDP struct {
	Name string `yaml:"name"`
	// EntityID is the federation entity identifier (issuer) of the IdP.
	EntityID string `yaml:"entity_id"`
	// EntityStatementURL overrides EntityID + "/.well-known/openid-federation".
	EntityStatementURL string `yaml:"entity_statement_url"`
	// AppLinkHost is the host serving Android App Links / iOS Universal Links
	// files (A_22661). Defaults to the authorization endpoint host.
	AppLinkHost string `yaml:"app_link_host"`
	// TICAFile optionally holds the TI component PKI CA certificates (PEM)
	// used to verify the x5c chain of ID token signatures (A_22655-03).
	TICAFile string `yaml:"ti_ca_file"`
	// SigningCertRoleOID optionally names an OID that must appear in the ID
	// token signing certificate (technical role oid_idpd_sek).
	SigningCertRoleOID string `yaml:"signing_cert_role_oid"`

	tiPool *x509.CertPool
}

type FederationMaster struct {
	EntityID string `yaml:"entity_id"`
}

type Fachdienst struct {
	ClientID    string `yaml:"client_id"`
	RedirectURI string `yaml:"redirect_uri"`
	// Scope requested in PAR. Defaults to openid plus urn:telematik:versicherter
	// and urn:telematik:display_name.
	Scope string `yaml:"scope"`
	// UnregisteredScope is a scope the IdP supports but that is not registered
	// for this Fachdienst at the Federation Master (A_22966-02).
	UnregisteredScope string `yaml:"unregistered_scope"`
	// UnregisteredRedirectURI is a redirect URI not registered for the
	// Fachdienst. Defaults to a URI derived from RedirectURI.
	UnregisteredRedirectURI string `yaml:"unregistered_redirect_uri"`
	ACRValues               string `yaml:"acr_values"`
	// TLSCert/TLSKey: the self-signed TLS client certificate published in the
	// Fachdienst's entity statement (self_signed_tls_client_auth).
	TLSCert string `yaml:"tls_cert"`
	TLSKey  string `yaml:"tls_key"`
	// EncKey is the private key (PEM or JWK) of the Fachdienst's encryption key
	// (use=enc) used to decrypt ID tokens (A_23193-01).
	EncKey string `yaml:"enc_key"`
	// EncKeyID is the kid of that key in the Fachdienst's jwks.
	EncKeyID string `yaml:"enc_key_id"`
	// IDTokenVersions mirrors metadata.openid_relying_party.ti_features_supported
	// .id_token_version_supported of the Fachdienst (default ["1.0.0"]).
	IDTokenVersions []string `yaml:"id_token_version_supported"`

	cert   tls.Certificate
	encKey crypto.PrivateKey
}

// Login configures how the resource owner is authenticated at the
// authorization endpoint. Only "form" (scripted HTML forms) exists today;
// eGK, eID and SCRAM based methods are meant to be added as further
// Authenticator implementations.
type Login struct {
	Method   string           `yaml:"method"`
	Username string           `yaml:"username"`
	Password string           `yaml:"password"`
	Steps    []useragent.Step `yaml:"steps"`
}

type TLS struct {
	// CAFile adds CA certificates for connections made by the test kit. The
	// A_22943 check always verifies against the system roots.
	CAFile             string `yaml:"ca_file"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
}

// Load reads and validates a sekidp-ctk config file. Relative file paths are
// resolved against the config file's directory.
func Load(path string) (*Config, error) {
	var c Config
	if err := yamlenv.Decode(path, &c); err != nil {
		return nil, err
	}
	base := filepath.Dir(path)
	if err := c.prepare(base); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

func (c *Config) prepare(base string) error {
	var errs []string
	add := func(format string, args ...any) { errs = append(errs, fmt.Sprintf(format, args...)) }
	if c.Timeout.Duration == 0 {
		c.Timeout.Duration = 20 * time.Second
	}
	if c.IDP.EntityID == "" {
		add("idp.entity_id is required")
	} else if u, err := url.Parse(c.IDP.EntityID); err != nil || !u.IsAbs() {
		add("idp.entity_id must be an absolute URL")
	}
	if c.IDP.EntityStatementURL == "" && c.IDP.EntityID != "" {
		c.IDP.EntityStatementURL = strings.TrimSuffix(c.IDP.EntityID, "/") + "/.well-known/openid-federation"
	}
	if c.IDP.TICAFile != "" {
		pool := x509.NewCertPool()
		raw, err := os.ReadFile(resolve(base, c.IDP.TICAFile))
		if err != nil || !pool.AppendCertsFromPEM(raw) {
			add("idp.ti_ca_file: no PEM certificates could be read (%v)", err)
		}
		c.IDP.tiPool = pool
	}
	if c.FederationMaster != nil && c.FederationMaster.EntityID == "" {
		add("federation_master.entity_id is required when federation_master is set")
	}
	for key, fd := range map[string]*Fachdienst{"fachdienst": c.Fachdienst, "fachdienst_b": c.FachdienstB} {
		if fd == nil {
			continue
		}
		if err := fd.prepare(base); err != nil {
			add("%s: %v", key, err)
		}
	}
	if c.Login.Method == "" {
		c.Login.Method = "form"
	}
	if _, ok := authenticators[c.Login.Method]; !ok {
		add("login.method %q is not supported (supported: %s)", c.Login.Method, strings.Join(authenticatorNames(), ", "))
	}
	if c.TLS.CAFile != "" {
		c.TLS.CAFile = resolve(base, c.TLS.CAFile)
	}
	if len(errs) > 0 {
		return fmt.Errorf("invalid config:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}

func (fd *Fachdienst) prepare(base string) error {
	var errs []string
	if fd.ClientID == "" {
		errs = append(errs, "client_id is required")
	}
	if fd.RedirectURI == "" {
		errs = append(errs, "redirect_uri is required")
	}
	if fd.Scope == "" {
		fd.Scope = "openid urn:telematik:display_name urn:telematik:versicherter"
	}
	if fd.ACRValues == "" {
		fd.ACRValues = "gematik-ehealth-loa-high"
	}
	if len(fd.IDTokenVersions) == 0 {
		fd.IDTokenVersions = []string{"1.0.0"}
	}
	if fd.UnregisteredRedirectURI == "" && fd.RedirectURI != "" {
		fd.UnregisteredRedirectURI = strings.TrimSuffix(fd.RedirectURI, "/") + "/ctk-unregistered"
	}
	if fd.TLSCert == "" || fd.TLSKey == "" {
		errs = append(errs, "tls_cert and tls_key are required (self_signed_tls_client_auth)")
	} else {
		cert, err := tls.LoadX509KeyPair(resolve(base, fd.TLSCert), resolve(base, fd.TLSKey))
		if err != nil {
			errs = append(errs, "tls_cert/tls_key: "+err.Error())
		}
		fd.cert = cert
	}
	if fd.EncKey != "" {
		k, err := loadPrivateKey(resolve(base, fd.EncKey))
		if err != nil {
			errs = append(errs, "enc_key: "+err.Error())
		}
		fd.encKey = k
	}
	// gemSpec_IDP_FD A_23196: Fachdienste use only EC P-256 keys for TLS
	// authentication and token encryption; other keys would be rejected.
	if fd.cert.PrivateKey != nil && !isP256(fd.cert.PrivateKey) {
		errs = append(errs, "tls_key must be an EC P-256 key (gemSpec_IDP_FD A_23196)")
	}
	if fd.encKey != nil && !isP256(fd.encKey) {
		errs = append(errs, "enc_key must be an EC P-256 key (gemSpec_IDP_FD A_23196)")
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func isP256(k crypto.PrivateKey) bool {
	ec, ok := k.(*ecdsa.PrivateKey)
	return ok && ec.Curve == elliptic.P256()
}

func resolve(base, p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(base, p)
}

// loadPrivateKey reads a PEM (PKCS#8, EC or PKCS#1) or JWK private key.
func loadPrivateKey(path string) (crypto.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if block, _ := pem.Decode(raw); block != nil {
		if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			return k, nil
		}
		if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
			return k, nil
		}
		if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
			return k, nil
		}
		return nil, errors.New("unsupported PEM private key")
	}
	var jwk jose.JSONWebKey
	if err := json.Unmarshal(raw, &jwk); err != nil {
		return nil, fmt.Errorf("neither PEM nor JWK: %w", err)
	}
	if jwk.IsPublic() {
		return nil, errors.New("JWK is a public key; the private key is needed to decrypt ID tokens")
	}
	return jwk.Key, nil
}
