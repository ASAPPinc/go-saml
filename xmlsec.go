package saml

import (
	"crypto/rand"
	"errors"
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
// xmlsec1 is run out of process through `exec`
func SignRequest(xml string, privateKey string) (string, error) {
	return sign(xml, privateKey, xmlRequestID)
}

// SignResponse sign a SAML 2.0 Response
// xmlsec1 is run out of process through `exec`
func SignResponse(xml string, privateKey string) (string, error) {
	return sign(xml, privateKey, xmlResponseID)
}

func sign(xml string, privateKey string, id string) (string, error) {

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

	privateKeyInput, err := ioutil.TempFile(os.TempDir(), "tmpkp")
	if err != nil {
		return "", err
	}

	numBytes, err := privateKeyInput.WriteString(privateKey)
	if err != nil {
		return "", err
	}
	privateKeyInput.Close()
	defer deleteTempFile(privateKeyInput.Name())
	defer overwriteTempFile(privateKeyInput.Name(), numBytes)

	// fmt.Println("xmlsec1", "--sign", "--privkey-pem", privateKeyPath,
	// 	"--id-attr:ID", id,
	// 	"--output", samlXmlsecOutput.Name(), samlXmlsecInput.Name())
	output, err := exec.Command("xmlsec1", "--sign", "--privkey-pem", privateKeyInput.Name(),
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
func VerifyResponseSignature(xml string, publicCert string) error {
	return verify(xml, publicCert, xmlResponseID)
}

// VerifyRequestSignature verify signature of a SAML 2.0 AuthnRequest document
// `publicCertPath` must be a path on the filesystem, xmlsec1 is run out of process
// through `exec`
func VerifyRequestSignature(xml string, publicCert string) error {
	return verify(xml, publicCert, xmlRequestID)
}

// VerifyAssertionSignature verify signature of a SAML 2.0 Response document
// `publicCertPath` must be a path on the filesystem, xmlsec1 is run out of process
// through `exec`
func VerifyAssertionSignature(xml string, publicCert string) error {
	return verify(xml, publicCert, xmlAssertionID)
}

func verify(xml string, publicCert string, id string) error {
	samlXmlsecInput, err := ioutil.TempFile(os.TempDir(), "tmpgs")
	if err != nil {
		return err
	}

	samlXmlsecInput.WriteString(xml)
	samlXmlsecInput.Close()
	defer deleteTempFile(samlXmlsecInput.Name())

	publicCertInput, err := ioutil.TempFile(os.TempDir(), "tmppc")
	if err != nil {
		return err
	}

	numBytes, err := publicCertInput.WriteString(publicCert)
	if err != nil {
		return err
	}
	publicCertInput.Close()
	defer deleteTempFile(publicCertInput.Name())
	defer overwriteTempFile(publicCertInput.Name(), numBytes)

	//fmt.Println("xmlsec1", "--verify", "--pubkey-cert-pem", publicCertPath, "--id-attr:ID", id, samlXmlsecInput.Name())
	_, err = exec.Command("xmlsec1", "--verify", "--pubkey-cert-pem", publicCertInput.Name(), "--id-attr:ID", id, samlXmlsecInput.Name()).CombinedOutput()
	if err != nil {
		return errors.New("error verifing signature: " + err.Error())
	}
	return nil
}

func GetDecryptedXML(xml string, privateKey string) (string, error) {
	samlXmlsecInput, err := ioutil.TempFile(os.TempDir(), "tmpgs")
	if err != nil {
		return "", err
	}

	samlXmlsecInput.WriteString(xml)
	samlXmlsecInput.Close()
	defer deleteTempFile(samlXmlsecInput.Name())

	privateKeyInput, err := ioutil.TempFile(os.TempDir(), "tmpkp")
	if err != nil {
		return "", err
	}

	numBytes, err := privateKeyInput.WriteString(privateKey)
	if err != nil {
		return "", err
	}
	privateKeyInput.Close()
	defer deleteTempFile(privateKeyInput.Name())
	defer overwriteTempFile(privateKeyInput.Name(), numBytes)
	// fmt.Println("xmlsec1", "--decrypt", "--privkey-pem", keyPath, samlXmlsecInput.Name())
	output, err := exec.Command("xmlsec1", "--decrypt", "--privkey-pem", privateKeyInput.Name(), samlXmlsecInput.Name()).CombinedOutput()
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

func overwriteTempFile(filename string, len int) error {
	b := make([]byte, len)
	_, err := rand.Read(b)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(filename, b, 0600)
	if err != nil {
		return err
	}

	return nil
}
