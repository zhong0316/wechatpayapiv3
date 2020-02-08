package wechatpayv3

import (
	"io/ioutil"
	"net/http"
	"strconv"
	"time"
)

const WechatPay2Schema = "WECHATPAY2-SHA256-RSA2048"

type Credentials interface {
	GetSchema() string
	GetToken(req *http.Request) (string, error)
}

type WechatPay2Credentials struct {
	MerchantId string
	Signer     *PrivateKeySigner
}

func (WechatPay2Credentials) GetSchema() string {
	return WechatPay2Schema
}

func (cr WechatPay2Credentials) GetToken(req *http.Request) (string, error) {
	nonceStr, err := New(20)

	if err != nil {
		return "", err
	}

	ts := time.Now().Unix()

	msg, err := buildMessage(nonceStr, ts, req)
	if err != nil {
		return "", err
	}

	signRes, err := cr.Signer.Sign([]byte(msg))
	if err != nil {
		return "", err
	}

	token := "mchid=\"" + cr.MerchantId + "\"," +
		"nonce_str=\"" + nonceStr + "\"," +
		"timestamp=\"" + strconv.FormatInt(ts, 10) + "\"," +
		"serial_no=\"" + signRes.CertificateSerialNumber + "\"," +
		"signature=\"" + signRes.Sign + "\""

	return token, nil
}

func buildMessage(nonce string, ts int64, req *http.Request) (string, error) {
	uri := req.URL
	canonicalUrl := uri.Path
	if uri.Query() != nil && len(uri.Query()) > 0 {
		canonicalUrl += "?" + uri.RawQuery
	}

	res := req.Method + "\n" +
		canonicalUrl + "\n" +
		strconv.FormatInt(ts, 10) + "\n" +
		nonce + "\n"
	if req.Body != nil {
		body, err := ioutil.ReadAll(req.Body)
		if err != nil {
			return "", err
		}
		res += string(body) + "\n"
	} else {
		res += "\n"
	}
	return res, nil
}
