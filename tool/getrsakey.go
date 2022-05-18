package tool

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
)

// GetRsaKey 初始化Rsa的公钥，密钥
func GetRsaKey() error {

	//生成私钥文件
	// GenerateKey函数使用随机数据生成器random生成一对具有指定字位数的RSA密钥
	// 参数1: Reader是一个全局、共享的密码用强随机数生成器
	// 参数2: 秘钥的位数 - bit

	//私钥
	//1.使用 rsa 中的 GenerateKey 方法生成私钥
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	//2.通过 x509 标准将得到的 ras 私钥序列化为 ASN.1 的 DER 编码字符串
	x509PrivateKey := x509.MarshalPKCS1PrivateKey(privateKey)
	privateFile, err := os.Create(PrivateFileName)
	if err != nil {
		return err
	}
	defer privateFile.Close()
	//3.将私钥字符串设置到 pem 格式块中
	privateBlock := pem.Block{
		Type:  PrivateKeyPrefix,
		Bytes: x509PrivateKey, // 内容解码后的数据，一般是DER编码的ASN.1结构
	}

	//4.通过 pem 将设置好的数据进行编码，并写入文件中
	if err = pem.Encode(privateFile, &privateBlock); err != nil {
		return err
	}

	//公钥
	//1.从得到的私钥对象中将公钥信息取出
	publicKey := privateKey.PublicKey

	//2.通过 x509 标准将得到 的 rsa 公钥序列化为字符串
	x509PublicKey, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		panic(err)
	}

	publicFile, _ := os.Create(PublicFileName)
	defer publicFile.Close()

	//3.将公钥字符串设置到 pem 格式块中
	publicBlock := pem.Block{
		Type:  PublicKeyPrefix,
		Bytes: x509PublicKey,
	}
	//4.通过 pem 将设置好的数据进行编码，并写入文件
	if err = pem.Encode(publicFile, &publicBlock); err != nil {
		return err
	}
	return nil
}

// GetRSAPublicKey 读取公钥
func GetRSAPublicKey(path string) *rsa.PublicKey {
	//读取公钥内容
	file, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	info, _ := file.Stat()
	buf := make([]byte, info.Size())
	file.Read(buf)
	//pem解码
	block, _ := pem.Decode(buf)
	//x509解码
	publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	publicKey := publicKeyInterface.(*rsa.PublicKey)
	return publicKey
}

// GetRSAPrivateKey 读取RSA私钥
func GetRSAPrivateKey(path string) *rsa.PrivateKey {
	//读取文件内容
	file, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	info, _ := file.Stat()
	buf := make([]byte, info.Size())
	file.Read(buf)
	//pem解码
	block, _ := pem.Decode(buf)
	//X509解码
	privateKey, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	return privateKey
}
