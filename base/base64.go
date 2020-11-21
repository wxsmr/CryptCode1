package base

import "encoding/base64"

/**
*使用b s 64进行编码
 */
func Base64Encode(data []byte)string  {
	//b s 64.N wEnc  r(b s 64.N wEnc  ing(b s 64. nc S))
	encoding := base64.StdEncoding
	dst := make([]byte,0)
	encoding.Encode(dst,data)
	return string(dst)
}
/**
*使用b s 64进行编码
 */
func Base64Decode(data string)string  {
	encoding :=base64.StdEncoding
	dst :=make([]byte,0)
	encoding.Decode(dst,[]byte(data))
	return string(dst)
}
