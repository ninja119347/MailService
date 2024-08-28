// 用户控制层
package controller

import (
	"admin-go-api/api/dto"
	"admin-go-api/api/service"
	"admin-go-api/common/result"
	"admin-go-api/pkg/jwt"
	"admin-go-api/pkg/log"
	"strings"

	"github.com/gin-gonic/gin"
)

// @Summary 用户登录接口
// @Description 用户登录接口
// @Produce json
// @Param data body dto.LoginDto true "data"
// @Success 200 {object} result.Result
// @Router /api/login [post]
func Login(c *gin.Context) {
	var dto dto.LoginDto
	//绑定参数将HTTP request中的json参数绑定到dto中
	_ = c.BindJSON(&dto)
	service.SysAdminService().Login(c, dto)
}

// @Summary 发送邮件接口
// @Description 发送邮件接口
// @Produce json
// @Param data body dto.SendDto true "data"
// @Success 200 {object} result.Result
// @Router /api/m/core/email [post]
func Send(c *gin.Context) {
	var dto dto.SendDto
	//绑定参数将HTTP request中的json参数绑定到dto中
	_ = c.BindJSON(&dto)
	log.Log().Info("dto: ", dto)
	service.SysAdminService().Send(c, dto)
	//appName := c.Query("L-APP-NAME")

	// 是不是和AuthMiddleware重复判断了 ===================================================
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

	// // 验证 token
	claims, err := jwt.ValidateToken(parts[1])
	if err != nil {
		result.Failed(c, result.ApiCode.MailTokenError, result.ApiCode.GetMessage(result.ApiCode.MailTokenError))
		c.Abort()
		return
	}

	// ==========================================================

	if dto.Users == nil {
		result.Failed(c, result.ApiCode.MailUsersError, result.ApiCode.GetMessage(result.ApiCode.MailUsersError))
	}

	if dto.Bid != "SPW" && dto.Bid != "APW" {
		result.Failed(c, result.ApiCode.MailBidError, result.ApiCode.GetMessage(result.ApiCode.MailBidError))
	}

	if dto.Data.Type != "1" && dto.Data.Type != "2" {
		result.Failed(c, result.ApiCode.MailTypeError, result.ApiCode.GetMessage(result.ApiCode.MailTypeError))
	}

	if dto.Data.Language == "" {
		result.Failed(c, result.ApiCode.MailLanguageError, result.ApiCode.GetMessage(result.ApiCode.MailLanguageError))
	}

	if claims.App_name == "uniupdate" && dto.Bid != "UPW" {
		result.Failed(c, result.ApiCode.MailAppnameBidError, result.ApiCode.GetMessage(result.ApiCode.MailAppnameBidError))
	}

	if claims.App_name == "aimonitor" && dto.Bid != "APW" {
		result.Failed(c, result.ApiCode.MailAppnameBidError, result.ApiCode.GetMessage(result.ApiCode.MailAppnameBidError))
	}

}
