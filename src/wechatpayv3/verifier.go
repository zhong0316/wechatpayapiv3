package wechatpayv3

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"github.com/tidwall/gjson"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"time"
)

// 微信支付平台证书下载地址
const WechatPlatformCertsDownloadUrl = "https://api.mch.weixin.qq.com/v3/certificates"

type Verifier interface {
	verify(serialNumber string, message string, signature string) (bool, error)
}

type CertificatesVerifier struct {
	Certificates map[string]*x509.Certificate
}

func (v CertificatesVerifier) withCertificates(certs []*x509.Certificate) {
	if certs != nil && len(certs) > 0 {
		for _, cert := range certs {
			v.Certificates[cert.SerialNumber.String()] = cert
		}
	}
}

func (v CertificatesVerifier) verify(merchantSerialNumber string, message string, signature string) (bool, error) {
	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, err
	}
	cert, ok := v.Certificates[merchantSerialNumber]
	if !ok {
		return false, errors.New("微信支付平台证书序列号非法")
	}
	err = cert.CheckSignature(x509.SHA256WithRSA, []byte(message), sigBytes)

	if err != nil {
		return false, err
	}
	return true, nil
}

type AutoUpdateCertificatesVerifier struct {
	CertificatesVerifier *CertificatesVerifier
	Credentials          *WechatPay2Credentials
	ApiV3Key             string
	lock                 *sync.Mutex
	lastUpdateTs         int64
}

func (v AutoUpdateCertificatesVerifier) verify(serialNumber string, message string, signature string) (bool, error) {
	if v.lastUpdateTs == 0 || time.Now().Unix()-v.lastUpdateTs > 3600 ||
		v.CertificatesVerifier.Certificates == nil || len(v.CertificatesVerifier.Certificates) == 0 {
		v.lock.Lock()
		defer v.lock.Unlock()
		err := v.autoUpdateCert()
		if err != nil {
			return false, err
		}
		v.lastUpdateTs = time.Now().Unix()
	}

	return v.CertificatesVerifier.verify(serialNumber, message, signature)
}

// 一个小时自动更新微信支付平台证书
func (v AutoUpdateCertificatesVerifier) autoUpdateCert() error {
	cli := ApiV3Client{
		HttpClient:  http.DefaultClient,
		Credentials: v.Credentials,
		// 初次下载平台证书时不验签
		Validator: NoopValidator{},
	}
	if v.CertificatesVerifier != nil {
		cli.Validator = WechatPay2Validator{Verifier: v.CertificatesVerifier}
	}
	certReq, err := http.NewRequest("GET", WechatPlatformCertsDownloadUrl, nil)
	if err != nil {
		return err
	}

	res, err := cli.Do(certReq)
	if err != nil {
		return err
	}

	rawBody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}

	bodyRes := gjson.Parse(string(rawBody))

	dataRes := bodyRes.Get("data").Array()
	apiV3Key := v.ApiV3Key
	if len(dataRes) > 0 {
		for _, dataNode := range dataRes {
			certNode := dataNode.Get("encrypt_certificate")
			associatedData := strings.ReplaceAll(certNode.Get("associated_data").Str, "\"", "")
			nonce := strings.ReplaceAll(certNode.Get("nonce").Str, "\"", "")
			cipherText := strings.ReplaceAll(certNode.Get("ciphertext").Str, "\"", "")
			certRaw, err := ApiV3Aes256GCMDecrypt([]byte(associatedData), []byte(nonce), []byte(cipherText), []byte(apiV3Key))
			if err != nil {
				return err
			}

			cert, err := ParseX509Cert(certRaw)
			if err != nil {
				return err
			}

			if cert != nil {
				v.CertificatesVerifier.Certificates[cert.SerialNumber.String()] = cert
			}
		}
	}

	return nil
}
