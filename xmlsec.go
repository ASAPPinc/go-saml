package saml

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
)

const (
	xmlResponseID  = "urn:oasis:names:tc:SAML:2.0:protocol:Response"
	xmlRequestID   = "urn:oasis:names:tc:SAML:2.0:protocol:AuthnRequest"
	xmlAssertionID = "urn:oasis:names:tc:SAML:2.0:assertion:Assertion"
)

// SignRequest sign a SAML 2.0 AuthnRequest
// `privateKeyPath` must be a path on the filesystem, xmlsec1 is run out of process
// through `exec`
func SignRequest(xml string, privateKeyPath string) (string, error) {
	return sign(xml, privateKeyPath, xmlRequestID)
}

// SignResponse sign a SAML 2.0 Response
// `privateKeyPath` must be a path on the filesystem, xmlsec1 is run out of process
// through `exec`
func SignResponse(xml string, privateKeyPath string) (string, error) {
	return sign(xml, privateKeyPath, xmlResponseID)
}

func sign(xml string, privateKeyPath string, id string) (string, error) {

	samlXmlsecInput, err := ioutil.TempFile(os.TempDir(), "tmpgs")
	if err != nil {
		return "", err
	}
	defer deleteTempFile(samlXmlsecInput.Name())
	samlXmlsecInput.WriteString("<?xml version='1.0' encoding='UTF-8'?>\n")
	samlXmlsecInput.WriteString(xml)
	samlXmlsecInput.Close()

	samlXmlsecOutput, err := ioutil.TempFile(os.TempDir(), "tmpgs")
	if err != nil {
		return "", err
	}
	defer deleteTempFile(samlXmlsecOutput.Name())
	samlXmlsecOutput.Close()

	// fmt.Println("xmlsec1", "--sign", "--privkey-pem", privateKeyPath,
	// 	"--id-attr:ID", id,
	// 	"--output", samlXmlsecOutput.Name(), samlXmlsecInput.Name())
	output, err := exec.Command("xmlsec1", "--sign", "--privkey-pem", privateKeyPath,
		"--id-attr:ID", id,
		"--output", samlXmlsecOutput.Name(), samlXmlsecInput.Name()).CombinedOutput()
	if err != nil {
		return "", errors.New(err.Error() + " : " + string(output))
	}

	samlSignedRequest, err := ioutil.ReadFile(samlXmlsecOutput.Name())
	if err != nil {
		return "", err
	}
	samlSignedRequestXML := strings.Trim(string(samlSignedRequest), "\n")
	return samlSignedRequestXML, nil
}

// VerifyResponseSignature verify signature of a SAML 2.0 Response document
// `publicCertPath` must be a path on the filesystem, xmlsec1 is run out of process
// through `exec`
func VerifyResponseSignature(xml string, publicCertPath string) error {
	fmt.Println("verifying response")
	return verify(xml, publicCertPath, xmlResponseID)
}

// VerifyRequestSignature verify signature of a SAML 2.0 AuthnRequest document
// `publicCertPath` must be a path on the filesystem, xmlsec1 is run out of process
// through `exec`
func VerifyRequestSignature(xml string, publicCertPath string) error {
	return verify(xml, publicCertPath, xmlRequestID)
}

// VerifyAssertionSignature verify signature of a SAML 2.0 Response document
// `publicCertPath` must be a path on the filesystem, xmlsec1 is run out of process
// through `exec`
func VerifyAssertionSignature(xml string, publicCertPath string) error {
	fmt.Println("verifying assertion")
	return verify(xml, publicCertPath, xmlAssertionID)
}

func verify(xml string, publicCertPath string, id string) error {
	//Write saml to
	samlXmlsecInput, err := ioutil.TempFile(os.TempDir(), "tmpgs")
	if err != nil {
		return err
	}

	samlXmlsecInput.WriteString(xml)
	samlXmlsecInput.Close()
	defer deleteTempFile(samlXmlsecInput.Name())

	//fmt.Println("xmlsec1", "--verify", "--pubkey-cert-pem", publicCertPath, "--id-attr:ID", id, samlXmlsecInput.Name())
	_, err = exec.Command("xmlsec1", "--verify", "--pubkey-cert-pem", publicCertPath, "--id-attr:ID", id, samlXmlsecInput.Name()).CombinedOutput()
	ioutil.WriteFile("SAMLTesting2.xml", []byte(xml), 0644)
	if err != nil {
		fmt.Println(err)
		return errors.New("error verifing signature: " + err.Error())
	}
	return nil
}

func GetDecryptedXML(xml, keyPath string) (string, error) {
	samlXmlsecInput, err := ioutil.TempFile(os.TempDir(), "tmpgs")
	if err != nil {
		return "", err
	}

	samlXmlsecInput.WriteString(xml)
	samlXmlsecInput.Close()
	defer deleteTempFile(samlXmlsecInput.Name())
	// fmt.Println("xmlsec1", "--decrypt", "--privkey-pem", keyPath, samlXmlsecInput.Name())
	output, err := exec.Command("xmlsec1", "--decrypt", "--privkey-pem", keyPath, samlXmlsecInput.Name()).CombinedOutput()
	if err != nil {
		return "", err
	}

	return strings.Trim(string(output), "\n"), nil
}

// deleteTempFile remove a file and ignore error
// Intended to be called in a defer after the creation of a temp file to ensure cleanup
func deleteTempFile(filename string) {
	_ = os.Remove(filename)
}
