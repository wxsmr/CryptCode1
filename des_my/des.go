package des_my

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"fmt"
)

/**
 * 使用DES算法对明文进行加密，使用秘钥key
 */
func DESEnCrypt(data []byte, key []byte) ([]byte, error) {
	//三要素：key、data、mode
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	fmt.Println(block)
	//尾部填充
	paddingSize := block.BlockSize() - len(data)%block.BlockSize()
	paddingText := bytes.Repeat([]byte{byte(paddingSize)}, paddingSize)
	originData := append(data,paddingText...)
	blockMode := cipher.NewCBCEncrypter(block, key)
	cipherData := make([]byte, len(originData))
	blockMode.CryptBlocks(cipherData, originData)
	return cipherData, nil
}

/**
 * 使用DES算法对密文进行解密，使用key作为秘钥
 */
func DESDeCrypt(data []byte, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	fmt.Println(block)
	//blockMode := cipher.NewCBCDecrypter(block, key)
	//originData := make([]byte, len(data))
	//blockMode.CryptBlocks(originData, data)
	//originData = utils.ClearPKCS5Padding(originData, block.BlockSize())
	paddingSize := block.BlockSize() - len(data)%block.BlockSize()
	paddingText := bytes.Repeat([]byte{byte(paddingSize)}, paddingSize)
	originData := append(data,paddingText...)
	blockMode := cipher.NewCBCEncrypter(block, key)
	cipherData := make([]byte, len(originData))
	blockMode.CryptBlocks(cipherData, originData)
	return originData, nil

}

