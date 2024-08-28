// 鉴权中间件
package middleware

import (
	"admin-go-api/api/dao"
	"admin-go-api/common/constant"
	"admin-go-api/common/result"
	"admin-go-api/pkg/jwt"
	"github.com/gin-gonic/gin"
	"strings"
)

func AuthMiddleware() func(c *gin.Context) {
	return func(c *gin.Context) {
		// 是不是和Send重复判断了 ===================================================
		authHeader := c.Request.Header.Get("Authorization")
		if authHeader == "" {
			result.Failed(c, result.ApiCode.MailHeaderError, result.ApiCode.GetMessage(result.ApiCode.MailHeaderError))
			c.Abort()
			return
		}
		parts := strings.SplitN(authHeader, " ", 2)
		if !(len(parts) == 2 && parts[0] == "Bearer") {
			result.Failed(c, result.ApiCode.MailHeaderError, result.ApiCode.GetMessage(result.ApiCode.MailHeaderError))
			c.Abort()
			return
		}
		// 验证 token
		claims, err := jwt.ValidateToken(parts[1])
		if err != nil {
			result.Failed(c, result.ApiCode.MailTokenError, result.ApiCode.GetMessage(result.ApiCode.MailTokenError))
			c.Abort()
			return
		}
		// ==========================================================

		//验证AppName一致
		AppName := c.Request.Header.Get("L-APP-NAME")
		if AppName != claims.App_name || AppName == "" {
			result.Failed(c, result.ApiCode.MailAppnameError, result.ApiCode.GetMessage(result.ApiCode.MailAppnameError))
			c.Abort()
			return
		}

		appName, _ := dao.CheckAppNameExists(AppName)
		if !appName {
			result.Failed(c, uint(result.ApiCode.MailAppnameExistsError), result.ApiCode.GetMessage(result.ApiCode.MailAppnameExistsError))
			c.Abort()
			return
		}

		// 将用户信息存储在上下文中
		c.Set(constant.ContexkeyUserObj, claims)
		c.Next()
	}
}
