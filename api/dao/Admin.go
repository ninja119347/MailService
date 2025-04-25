// 用户 数据层
package dao

import (
	"admin-go-api/api/entity"
	"admin-go-api/pkg/db"
	"os"
)

// const (
//
//	DEFAULT_KEY   = "Default"
//	UNIUPDATE_KEY = "0725#uni#UPDATE"
//	AIMONITOR_KEY = "#ai@monitor0725"
//	SIGN_KEY      = "sign$Lenovo1984"
//
// )
// 常量定义
var (
	DEFAULT_KEY   = getEnv("DEFAULT_KEY", "Default")             // 默认密钥
	UNIUPDATE_KEY = getEnv("UNIUPDATE_KEY", "Default")           // UniUpdate密钥
	AIMONITOR_KEY = getEnv("AIMONITOR_KEY", "Default")           // AI监控密钥
	SIGN_KEY      = getEnv("SIGN_KEY", "Default")                // 签名密钥
	MAIL_PORT     = getEnv("MAIL_PORT", "80")                    // 邮件发送地址
	AUTOBUILD_KEY = getEnv("AUTOBUILD_KEY", "sign_Lenovo119347") // 自动构建密钥
)

// 获取环境变量值，如果未设置则返回默认值
func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}
func CheckAppNameExists(appName string) (bool, error) {
	var count int64
	err := db.Db.Model(&entity.SysAdmin{}).Where("AppName = ?", appName).Count(&count).Error
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func GetEmailInfo() (email entity.Email, err error) {
	err = db.Db.Model(&entity.Email{}).Where("id!=''").First(&email).Error
	if err != nil {
		return email, err
	}
	return email, err
}
