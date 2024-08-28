package util

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"strconv"

	"github.com/gotomicro/ego/core/elog"
)

// AES ECB模式的加密解密
type AesTool struct {
	//128 192  256位的其中一个 长度 对应分别是 16 24  32字节长度
	Key       string
	BlockSize int
}

func NewAesTool(key string, blockSize int) *AesTool {
	return &AesTool{Key: key, BlockSize: blockSize}
}

func (this *AesTool) padding(src []byte) []byte {
	//填充个数
	paddingCount := aes.BlockSize - len(src)%aes.BlockSize
	if paddingCount == 0 {
		return src
	} else {
		//填充数据
		return append(src, bytes.Repeat([]byte{byte(0)}, paddingCount)...)
	}
}

// unpadding
func (this *AesTool) unPadding(src []byte) []byte {
	for i := len(src) - 1; ; i-- {
		if src[i] != 0 {
			return src[:i+1]
		}
	}
	return nil
}

func (this *AesTool) Encrypt(src []byte) ([]byte, error) {
	elog.Error("Key==============" + this.Key)

	//key只能是 16 24 32长度
	block, err := aes.NewCipher([]byte(this.Key))

	if err != nil {
		return nil, err
	}

	//padding
	src = this.padding(src)

	//返回加密结果
	encryptData := make([]byte, len(src))
	elog.Error("Src==============" + strconv.Itoa(len(src)))

	//存储每次加密的数据
	tmpData := make([]byte, this.BlockSize)
	elog.Error("BlockSize==============" + strconv.Itoa(this.BlockSize))

	//分组分块加密
	for index := 0; index < len(src); index += this.BlockSize {
		block.Encrypt(tmpData, src[index:index+this.BlockSize])
		copy(encryptData, tmpData)
	}
	elog.Error("End encryptData==============")

	return encryptData, nil
}
func (this *AesTool) Decrypt(src []byte) ([]byte, error) {

	// elog.Error("Key==============" + this.Key)
	//key只能是 16 24 32长度
	block, err := aes.NewCipher([]byte(this.Key))

	if err != nil {
		return nil, err
	}
	//返回加密结果
	decryptData := make([]byte, len(src))
	// elog.Error("Src==============" + strconv.Itoa(len(src)))
	//存储每次加密的数据
	tmpData := make([]byte, this.BlockSize)
	// elog.Error("BlockSize==============" + strconv.Itoa(this.BlockSize))

	//分组分块加密
	for index := 0; index < len(src); index += this.BlockSize {
		block.Decrypt(tmpData, src[index:index+this.BlockSize])
		copy(decryptData, tmpData)
	}
	// elog.Error("End decryptData==============")
	return this.unPadding(decryptData), nil
}

// 测试AES ECB 加密解密
func TestEncryptDecrypt() {
	key := "key"
	blockSize := 16
	tool := NewAesTool(key, blockSize)
	//加密
	encryptBytes, _ := base64.StdEncoding.DecodeString("text")
	encryptData, _ := tool.Encrypt(encryptBytes)
	fmt.Println(encryptData)
	//解密
	decryptData, _ := tool.Decrypt(encryptData)
	fmt.Println(decryptData)
}
