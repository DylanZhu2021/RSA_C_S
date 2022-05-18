package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"go_code/RSA/RSA_C_S/tool"
	"net"
	"os"
	"strings"
	"time"
)

type tran struct {
	Ciphertext []byte //密文
	Csign      []byte //签名
}

func main() {

	//初始化公钥与私钥
	tool.GetRsaKey()

	var message string
	//连接服务器！！
	conn, err := net.Dial("tcp", "127.0.0.1:8088")
	if err != nil {
		panic(err)
	}

	reader := bufio.NewReader(os.Stdin)

	//循环发送message给server
	for {
		fmt.Println("请输入明文：")
		var t tran
		message, err = reader.ReadString('\n')
		if err != nil {
			panic(err)
		}
		message = strings.Trim(message, "\n\r")

		if message == "exit" {
			fmt.Println("client logout!")
			break
		}

		fmt.Println("你发送的明文是：", message)
		//生成密文
		t.Ciphertext = tool.RSAEncrypt([]byte(message), tool.PublicFileName)

		if err == nil {
			time.Sleep(time.Duration(1) * time.Second)
			fmt.Println("明文加密后的密文是：", t.Ciphertext)
		} else {
			fmt.Println("明文加密错误，err=", err)
		}

		//生成签名
		t.Csign, err = tool.GetSign([]byte(message), tool.PrivateFileNameServer)
		if err != nil {
			fmt.Println("get sign error,err=", err)

		}
		time.Sleep(time.Duration(1) * time.Second)
		fmt.Println("已经生成密文对应的签名！")

		//将结构体序列化！
		tranjson, err := json.Marshal(t)
		if err != nil {
			fmt.Println("Marshal error!err=", err)
		}
		//发送给服务器数据
		_, err = conn.Write(tranjson)
		if err != nil {
			fmt.Println("发送数据给服务器错误！")
		}
		time.Sleep(time.Duration(1) * time.Second)
		fmt.Println("密文和签名已经发送成功！")
	}

}
