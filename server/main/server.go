package main

import (
	"encoding/json"
	"fmt"
	"go_code/RSA/RSA_C_S/tool"
	"log"
	"net"
)

type tran struct {
	Ciphertext []byte //明文加密后的密文
	Csign      []byte //签名！（密文和摘要）
}

func server() {

	lis, err := net.Listen("tcp", "127.0.0.1:8088")
	if err != nil {
		log.Fatal(err)
	}
	defer lis.Close()

	//循环等待客户端被访问
	for {
		conn, err := lis.Accept()
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("客户端连接成功！连接信息： %v,ip is %v\n", conn, conn.RemoteAddr().String())

		go handleConn(conn)
	}

}

func handleConn(conn net.Conn) {

	defer conn.Close()

	for {

		var t tran
		fmt.Println("等待客户端发送信息！")

		tranjson := make([]byte, 2048)

		//接收客户端发送的数据！
		total, err := conn.Read(tranjson)
		if err != nil {
			log.Fatal(err)
			break
		}

		//反序列化！！得到结构体！
		err = json.Unmarshal(tranjson[:total], &t)
		if err != nil {
			fmt.Println("unmarshal error!err=", err)
		}

		//对密文解密！！！
		plainText := tool.RSADecrypt(t.Ciphertext, tool.PrivateFileNameServer)

		if err != nil {
			fmt.Println("解密密文失败，err=", err)
		}

		//数字签名验证的结果！
		res := tool.VeriFySign(plainText, t.Csign, tool.PublicFileNameServer)
		if res {
			fmt.Println("服务器端已经接收到来自客户端的密文和对应的签名！")
			fmt.Println("服务器收到的密文是：", t.Ciphertext)
			fmt.Println("客户端发送的明文是：", string(plainText))
			fmt.Println("签名通过验证！")
		} else {
			fmt.Println("服务器端已经接收到来自客户端的密文和对应的签名！")
			fmt.Println("服务器收到的密文是：", t.Ciphertext)
			fmt.Println("客户端发送的明文是：", string(plainText))
			fmt.Println("签名未通过验证！")
		}
	}
}

func main() {

	server()
}
