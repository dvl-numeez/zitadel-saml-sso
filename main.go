package main

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
)

func main() {
	rootURL, err := url.Parse("http://localhost:7777")
	if err != nil {
		log.Fatal(err)
	}
	// idpMetadataFile, err := os.ReadFile("metadata.xml")
	// if err != nil {
	// 	log.Fatalf("cannot open IDP metadata: %v", err)
	// }

	// idpMetadata, err := samlsp.ParseMetadata(idpMetadataFile)
	// if err != nil {
	// 	log.Fatalf("cannot parse IDP metadata: %v", err)
	// }
	idpMetadata := mustLoadIDPMetadata()
	samlMiddleware, err := samlsp.New(samlsp.Options{
		URL:         *rootURL,
		Key:         mustLoadPrivateKey("saml.key"),
		Certificate: mustLoadCertificate("saml.crt"),
		IDPMetadata: idpMetadata,
	})
	if err != nil {
		log.Fatal(err)
	}
	samlMiddleware.ServiceProvider.AuthnNameIDFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

	http.Handle("/saml/", samlMiddleware) // includes /saml/metadata
	http.Handle("/saml/acs", samlMiddleware)
	http.Handle("/saml/slo", samlMiddleware)
	http.Handle("/hello", samlMiddleware.RequireAccount(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract user info
		session := samlsp.SessionFromContext(r.Context())
		if session == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte("Welcome, "))
		fmt.Fprintf(w, "Session: %+v\n", session)
	})))
	http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		_ = samlMiddleware.Session.DeleteSession(w, r)
		http.Redirect(w, r, "/", http.StatusFound)
	})
	log.Println("Listening on :7777...")
	log.Fatal(http.ListenAndServe(":7777", nil))
}

func mustLoadPrivateKey(path string) crypto.Signer {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("failed to read private key file: %v", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		log.Fatalf("invalid PEM block in private key file")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			log.Fatalf("failed to parse PKCS#1 private key: %v", err)
		}
		return key
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			log.Fatalf("failed to parse PKCS#8 private key: %v", err)
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			log.Fatal("private key does not implement crypto.Signer")
		}
		return signer
	default:
		log.Fatalf("unsupported key type: %s", block.Type)
		return nil
	}
}

func mustLoadCertificate(path string) *x509.Certificate {
	certPEM, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatalf("failed to read certificate: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		log.Fatal("failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("failed to parse certificate: %v", err)
	}
	return cert
}

func mustLoadIDPMetadata() *saml.EntityDescriptor {
	certPEM, err := os.ReadFile("idp.crt")
	if err != nil {
		log.Fatalf("failed to read IdP cert: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		log.Fatalf("failed to parse IdP cert PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("failed to parse IdP certificate: %v", err)
	}

	base64Cert := base64.StdEncoding.EncodeToString(cert.Raw)
	return &saml.EntityDescriptor{
		EntityID: "http://localhost:8080/saml/v2/metadata",
		IDPSSODescriptors: []saml.IDPSSODescriptor{
			{
				SingleSignOnServices: []saml.Endpoint{
					{
						Binding:  saml.HTTPRedirectBinding,
						Location: "http://localhost:8080/saml/v2/SSO",
					},
				},
				SSODescriptor: saml.SSODescriptor{
					SingleLogoutServices: []saml.Endpoint{
						{
							Binding:  saml.HTTPRedirectBinding,
							Location: "http://localhost:8080/saml/v2/SLO",
						},
					},
					RoleDescriptor: saml.RoleDescriptor{
						KeyDescriptors: []saml.KeyDescriptor{
							{
								Use: "signing",
								KeyInfo: saml.KeyInfo{
									X509Data: saml.X509Data{
										X509Certificates: []saml.X509Certificate{
											{
												Data: base64Cert,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

}
