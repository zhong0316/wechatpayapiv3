package wechatpayv3

import (
	"errors"
	"io/ioutil"
	"net/http"
)

type Validator interface {
	validate(response *http.Response) (bool, error)
}

// 初次下载证书时不验签
type NoopValidator struct {
}

// 使用微信支付平台证书验签
type WechatPay2Validator struct {
	Verifier *CertificatesVerifier
}

func (NoopValidator) validate(response *http.Response) (bool, error) {
	return true, nil
}

func (v WechatPay2Validator) validate(response *http.Response) (bool, error) {
	serialNo := response.Header.Get("Wechatpay-Serial")
	sign := response.Header.Get("Wechatpay-Signature")
	ts := response.Header.Get("Wechatpay-TimeStamp")
	nonce := response.Header.Get("Wechatpay-Nonce")
	body := response.Body
	bodyBytes, err := ioutil.ReadAll(body)

	if err != nil {
		return false, err
	}

	if serialNo == "" || sign == "" || ts == "" || nonce == "" {
		return false, errors.New("微信请求头部信息错误！")
	}

	message := ts + "\n" + nonce + "\n" + string(bodyBytes)

	return v.Verifier.verify(serialNo, message, sign)
}
