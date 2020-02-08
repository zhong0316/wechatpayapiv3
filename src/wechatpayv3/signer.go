package wechatpayv3

import (
	"crypto/rsa"
	"encoding/base64"
)

// 签名结果
type SignatureResult struct {
	Sign                    string
	CertificateSerialNumber string
}
type Signer interface {
	Sign(message []byte) (*SignatureResult, error)
}

// SHA256withRSA签名
type PrivateKeySigner struct {
	CertificateSerialNumber string
	PrivateKey              *rsa.PrivateKey
}

func (sg PrivateKeySigner) Sign(message []byte) (*SignatureResult, error) {
	signBytes, err := RsaSignWithSha256(message, sg.PrivateKey)
	if err != nil {
		return nil, err
	}

	sign := base64.StdEncoding.EncodeToString(signBytes)

	return &SignatureResult{
		Sign:                    sign,
		CertificateSerialNumber: sg.CertificateSerialNumber,
	}, nil
}
