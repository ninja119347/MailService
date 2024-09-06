// 系统常量
package constant

import "time"

const (

	//存登录结构体
	Claims = "claimsObject"
	// token过期时间
	TokenExpireDuration = time.Minute * 8
	// token最大刷新时间
	TokenMaxRefreshTime = time.Hour * 2
)
