package rsa

import (
	"CryptCode/utils"
	"crypto"
	_ "crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	_ "debug/dwarf"
	"encoding/pem"
	"flag"
	"os"
)

/**
*私钥:
*公钥:
*汉森堡:
 */
func CreatePairKeys()(*rsa.PrivateKey, error){
		//1,先生成私钥
		var bits int
		flag.IntVar(&bits, "b", 2048, "密钥长度")
		//fmt.Println(bits)
		privateKey, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, nil
		}
		//2,根据私钥生成公钥
		//publicKey := privateKey.Public()
		//3,将私钥和公钥进行返回
		return privateKey, nil
	}
/**
*根据给定的私钥数据，生成对应的pem文件
 */

func GeneratePemFileByPrivateKey(pri PublicKey) error {
	//根据PKCS1规则,序列化后的私钥
	priStream := x509.MarshalPKCS1PrivateKey(pri)

	//pem文件,此时,privateFile文件为空
	privatFile, err := os.Create("rsa_pri.pem") //存私钥的生成文件
	if err != nil {
		return err
	}
	//pem文件中的格式 结构体
	block := &pem.Block{
		Type:  "hhh",
		Bytes: priStream,
	}
	pubFile,err :=os.Create("rsa_pub.pem")
	if err !=nil{
		return err
	}
	return pem.Encode(pubFile,&block)
	//将准备好的格式内容写入到pem文件中
	err = pem.Encode(privatFile, block)
	if err != nil {
		return err
	}
	return nil
}
/**
*使用公钥生成对应的pem文件,持久化储存
 */
func GeneratePubFileByPubKey(pub rsa.PrivateKey)  {
	x509.MarshalPKCS1PrivateKey(&pub)
}
//================================第一种组合:公钥加密,私钥解密==================
	/**
	*使用RSA算法对数据进行加密,返回加密后的密文
	 */
func RSAEncrypt(key rsa.PublicKey, data []byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader,&key,data)
}
/**
*使用RSA算法对密文数据进行解密,返回解密后的明文
 */
func RSADecrypt(private *rsa.PrivateKey,cipher []byte)([]byte,error)  {
	return rsa.DecryptPKCS1v15(rand.Reader,private,cipher)
}

//============================第二组合:私钥签名,公钥验签===========================//

/**
*使用RSA算法对数据进行数字签名,并返回签名信息
 */
func RSASign(private *rsa.PrivateKey,data []byte)([]byte,error)  {
	hashed :=utils.Md5Hash(data)
	return rsa.SignPKCS1v15(rand.Reader,private,crypto.MD5,hashed)
}
/**
*使用RSA算法对数据进行签名验证,并返回签名验证的结果
*验证通过,返回true
*验证不通过,返回false,同时error中有错误信息
 */
func RSAVerify(pub rsa.PublicKey, signText []byte, text4 []byte) (bool, error) {
	hashed :=utils.Md5Hash(data)
	err := rsa.VerifyPKCS1v15(&pub,crypto.MD5,hashed,signText)
	return err ==nil,err
}
