package wechatpayv3

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"strings"
)

func DecodePEM(pemData string) (*pem.Block, error) {
	r := strings.NewReader(pemData)

	pemBytes, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	data, _ := pem.Decode(pemBytes)

	return data, nil
}

func ParseX509Cert(pemData string) (*x509.Certificate, error) {
	data, decodeErr := DecodePEM(pemData)

	if decodeErr != nil {
		return nil, decodeErr
	}

	var cert *x509.Certificate
	cert, parseErr := x509.ParseCertificate(data.Bytes)

	if parseErr != nil {
		return nil, parseErr
	}

	return cert, nil
}

func VerifyCert(pemData, CApemData string) bool {
	CAcert, parseErr := ParseX509Cert(CApemData)
	if parseErr != nil {
		return false
	}

	cert, parseErr := ParseX509Cert(pemData)
	if parseErr != nil {
		return false
	}

	verifyErr := cert.CheckSignatureFrom(CAcert)
	if verifyErr != nil {
		return false
	}

	return true
}
