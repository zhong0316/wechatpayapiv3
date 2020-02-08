package wechatpayv3

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
)

type ApiV3Client struct {
	HttpClient  *http.Client
	Credentials *WechatPay2Credentials
	Validator   Validator
}

func (c *ApiV3Client) WithHttpClient(httpClient *http.Client) {
	c.HttpClient = httpClient
}

func (c *ApiV3Client) WithMerchant(merchantId, certificateSerialNumber string, privateKey *rsa.PrivateKey) {
	c.Credentials = &WechatPay2Credentials{
		MerchantId: merchantId,
		Signer: &PrivateKeySigner{
			CertificateSerialNumber: certificateSerialNumber,
			PrivateKey:              privateKey,
		},
	}
}

func (c *ApiV3Client) WithValidator(validator Validator) {
	c.Validator = validator
}

func (c ApiV3Client) Do(req *http.Request) (*http.Response, error) {
	schema := c.Credentials.GetSchema()
	token, err := c.Credentials.GetToken(req)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", schema+" "+token)

	fmt.Println(req.Header.Get("Authorization"))

	res, err := c.HttpClient.Do(req)
	if err != nil {
		return res, err
	}

	valid, err := c.Validator.validate(res)

	if !valid {
		return res, errors.New("验签失败")
	}

	if err != nil {
		return res, err
	}

	return res, nil
}
