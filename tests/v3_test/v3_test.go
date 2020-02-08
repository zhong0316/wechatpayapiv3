package v3_test

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"
	"wechatpayapiv3/src/wechatpayv3"
)

func TestV3CertDown(t *testing.T) {
	mchId := ""
	mchSerialNumber := ""

	priKey, err := LoadPrivateKeyFile("")
	if err != nil {
		fmt.Println(err)
	}

	cli := wechatpayv3.ApiV3Client{
		HttpClient:  http.DefaultClient,
		Credentials: nil,
		Validator:   wechatpayv3.NoopValidator{},
	}
	cli.WithMerchant(mchId, mchSerialNumber, priKey)

	req, _ := http.NewRequest("GET", "https://api.mch.weixin.qq.com/v3/certificates", nil)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.108 Safari/537.36")
	res, err := cli.Do(req)

	if err != nil {
		fmt.Println(err)
	}

	bodyBytes, _ := ioutil.ReadAll(res.Body)
	fmt.Println(string(bodyBytes))
}

// Load private key from private key file
func LoadPrivateKeyFile(keyfile string) (*rsa.PrivateKey, error) {
	keybuffer, err := ioutil.ReadFile(keyfile)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode([]byte(keybuffer))
	if block == nil {
		return nil, errors.New("private key error!")
	}

	privatekey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("parse private key error!")
	}

	return privatekey.(*rsa.PrivateKey), nil
}
