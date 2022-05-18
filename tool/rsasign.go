package tool

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

// GetSign 对消息进行数字签名
func GetSign(msg []byte, path string) ([]byte, error) {
	//取得私钥
	privateKey := GetRSAPrivateKey(path)

	//计算散列值，将数据通过哈希函数生成信息摘要
	hash := sha256.New()
	hash.Write(msg)
	bytes := hash.Sum(nil)
	//SignPKCS1v15使用RSA PKCS#1 v1.5规定的RSASSA-PKCS1-V1_5-SIGN签名方案计算签名
	sign, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, bytes)

	return sign, err
}

// VeriFySign 验证数字签名
func VeriFySign(msg []byte, sign []byte, path string) bool {
	//取得公钥
	publicKey := GetRSAPublicKey(path)
	//计算消息散列值
	hash := sha256.New()
	hash.Write(msg)
	bytes := hash.Sum(nil)

	//验证数字签名
	err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, bytes, sign)
	return err == nil
}
