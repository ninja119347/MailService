// 用户服务层
package service

import (
	"admin-go-api/api/dao"
	"admin-go-api/api/dto"
	"admin-go-api/common/constant"
	"admin-go-api/common/result"
	"admin-go-api/common/util"
	"admin-go-api/pkg/jwt"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/gotomicro/ego/core/elog"
	gomail "gopkg.in/gomail.v2"
)

// 定义接口
type ISysAdminService interface {
	Login(c *gin.Context, dto dto.LoginDto)
	Send(c *gin.Context, dto dto.SendDto)
}

type SysAdminServiceImpl struct{}

var sysAdminServiceImpl = SysAdminServiceImpl{}

// 实现用户登录接口
// + appid解密
func (s SysAdminServiceImpl) Login(c *gin.Context, dto dto.LoginDto) {
	//校验参数
	err := validator.New().Struct(dto)
	if err != nil {
		result.Failed(c, uint(result.ApiCode.LoginRequestBodyError), result.ApiCode.GetMessage(result.ApiCode.LoginRequestBodyError))
		return
	}
	// log.Log().Info("shibai")
	// //查看时间是否超时
	// verifyTime := dto.IsUtraDataExpired()
	// if verifyTime {
	// 	elog.Errorf("登录时间超时: %v", err)
	// 	result.Failed(c, uint(result.ApiCode.LoginOutOfTime), result.ApiCode.GetMessage(result.ApiCode.LoginOutOfTime))
	// 	return
	// }

	//校验appId
	if dto.Id != "223" {
		result.Failed(c, uint(result.ApiCode.LoginIdError), result.ApiCode.GetMessage(result.ApiCode.LoginIdError))
	}

	nowTime := time.Now().Unix()
	if int64(dto.UltraData) > (nowTime + 86400) {
		result.Failed(c, uint(result.ApiCode.LoginUltraDataError), result.ApiCode.GetMessage(result.ApiCode.LoginUltraDataError))
	}

	app_id := dto.Id + dto.AppName + strconv.Itoa(int(dto.UltraData)) + dao.SIGN_KEY
	if dto.AppName == "uniupdate" {
		app_id = dto.Id + dto.AppName + strconv.Itoa(int(dto.UltraData)) + dao.UNIUPDATE_KEY
	} else if dto.AppName == "aimonitor" {
		app_id = dto.Id + dto.AppName + strconv.Itoa(int(dto.UltraData)) + dao.AIMONITOR_KEY
	}

	message := []byte(app_id)
	hash := sha512.New()
	hash.Write(message)
	bytes := hash.Sum(nil)
	hashCode := hex.EncodeToString(bytes)
	if strings.ToUpper(dto.AppId) != strings.ToUpper(hashCode) {
		result.Failed(c, uint(result.ApiCode.LoginAppidError), result.ApiCode.GetMessage(result.ApiCode.LoginAppidError))
	}

	//校验appName
	appName, _ := dao.CheckAppNameExists(dto.AppName)
	if !appName {
		result.Failed(c, uint(result.ApiCode.LoginAppnameError), result.ApiCode.GetMessage(result.ApiCode.LoginAppnameError))
		return
	}

	//生成token
	tokenString, expireTime, _ := jwt.GenerateTokenByAdmin(dto)
	result.Success(c, map[string]interface{}{"access_token": tokenString, "expire_at": expireTime, "max_refresh": constant.TokenMaxRefreshTime / time.Second, "timeout:": constant.TokenExpireDuration / time.Second})
}

// 实现发送邮件接口
// + uniupdate的解密算法
func (s SysAdminServiceImpl) Send(c *gin.Context, dto dto.SendDto) {
	//参数校验
	err := validator.New().Struct(dto)
	if err != nil {
		result.Failed(c, uint(result.ApiCode.MailRequestBodyError), result.ApiCode.GetMessage(result.ApiCode.MailRequestBodyError))
		return
	}

	//发送邮件
	param_bid := dto.Bid
	param_type := dto.Data.Type
	param_language := dto.Data.Language
	param_content := dto.Data.Content

	title := ""
	desc := ""

	if param_bid == "UPW" {
		ASE_KEY := "pzy0123456789pzy"
		blockSize := 16
		tool := util.NewAesTool(ASE_KEY, blockSize)
		encryptContent, _ := base64.StdEncoding.DecodeString(param_content)
		param_password, _ := tool.Decrypt([]byte(encryptContent))

		if param_type == "1" {
			if param_language == "zh-CN" {
				title = "Uniupdate 账户创建"
				desc = MailForUniupdateCreateCN(string(param_password))
			} else {
				title = "Uniupdate account creation"
				desc = MailForUniupdatCreate(string(param_password))
			}
		} else if param_type == "2" {
			if param_language == "zh-CN" {
				title = "Uniupdate 密码重置"
				desc = MailForUniupdateResetCN(string(param_password))
			} else {
				title = "Uniupdate password reset"
				desc = MailForUniupdatReset(string(param_password))
			}
		}
	} else if param_bid == "APW" {
		if param_language == "zh-CN" {
			title = "AI Monitor显示器系统提示"
			desc = MailForAimonitorCN(param_content)
		} else {
			title = "Notification from AI Monitor Team"
			desc = MailForAimonitor(param_content)
		}
	}

	if title != "" && desc != "" {
		if SendMailApi(dto.Users, title, desc) {
			response := result.EmailResponse{}
			response.ErrCode = int(result.ApiCode.ERROK)
			response.ErrMsg = "OK"
			response.Code = ""
			c.JSON(http.StatusOK, response)

		} else {
			response := result.EmailResponse{}
			response.ErrCode = int(result.ApiCode.ERRMAILSEND)
			response.ErrMsg = "Send failed"
			response.Code = ""
			c.JSON(http.StatusOK, response)
		}
	} else {
		response := result.EmailResponse{}
		response.ErrCode = int(result.ApiCode.ERRMAILSEND)
		response.ErrMsg = "send content null"
		response.Code = ""
		c.JSON(http.StatusOK, response)
	}
}

func SendMailApi(to []string, title, desc string) bool {
	for _, user := range to {
		if !util.EmailIsValid(user) {
			return false
		}
	}

	sendMailMass(to, title, desc)
	return true
}

func sendMailMass(to []string, title, message string) {
	mail, err := dao.GetEmailInfo()
	if err != nil {
		elog.Error(err.Error())
	}
	m := gomail.NewMessage()
	// Email Host EmailPassword sys
	m.SetHeader(`From`, mail.Email)
	m.SetHeader(`To`, to...)
	m.SetHeader(`Subject`, title)
	m.SetBody("text/html", message)
	d := gomail.NewDialer(mail.Host, 80, mail.Email, mail.EmailPassword)
	// 修改TLSconfig
	d.TLSConfig = &tls.Config{InsecureSkipVerify: true}
	if err := d.DialAndSend(m); err != nil {
		elog.Error(err.Error())
	}
}

func MailForUniupdateCreateCN(param string) (desc string) {
	desc = "<span style=\"font-size:20px;font-family: Microsoft YaHei\"> 亲爱的联想Uniupdate用户，我们已为您创建了该邮箱的账户。 <br></span>" +
		"<span style=\"font-size:20px;font-family: Microsoft YaHei\"> 您的初始密码为：<b>" + param + " </b><br></span>" +
		"<span style=\"font-size:20px;font-family: Microsoft YaHei\"> 请在登录后立即修改密码，谢谢！<br></span>"
	return desc
}

func MailForUniupdatCreate(param string) (desc string) {
	desc = "<span style=\"font-size:20px;font-family: Microsoft YaHei\"> Dear Lenovo Uniupdate users, we have created an account for you for this mailbox. <br></span>" +
		"<span style=\"font-size:20px;font-family: Microsoft YaHei\"> Your initial password is: <b>" + param + " </b><br></span>" +
		"<span style=\"font-size:20px;font-family: Microsoft YaHei\"> Please change your password immediately after login, thanks!<br></span>"
	return desc
}

func MailForUniupdateResetCN(param string) (desc string) {
	desc = "<span style=\"font-size:20px;font-family: Microsoft YaHei\"> 亲爱的联想Uniupdate用户，我们收到了您重置 Uniupdate 密码的申请。<br></span>" +
		"<span style=\"font-size:20px;font-family: Microsoft YaHei\"> 您的临时密码为：<b>" + param + " </b><br></span>" +
		"<span style=\"font-size:20px;font-family: Microsoft YaHei\"> 请在登录后立即修改密码，谢谢！<br></span>"
	return desc
}

func MailForUniupdatReset(param string) (desc string) {
	desc = "<span style=\"font-size:20px;font-family: Microsoft YaHei\"> Dear Lenovo Uniupdate users, we have received your request to reset your Uniupdate password. <br></span>" +
		"<span style=\"font-size:20px;font-family: Microsoft YaHei\"> Your temporary password is: <b>" + param + " </b><br></span>" +
		"<span style=\"font-size:20px;font-family: Microsoft YaHei\"> Please change your password immediately after login, thanks!<br></span>"
	return desc
}

func MailForAimonitorCN(param string) (desc string) {
	desc = "<span style=\"font-size:15px;font-family: Microsoft YaHei\"> 亲爱的AI Monitor用户，<br></span>" +
		"<span style=\"font-size:15px;font-family: Microsoft YaHei\"> 系统检测到您的显示器的<span style=\"color: red;\"><b>" + param + "</b></span>，如果不是您本人的操作，请检查显示器的使用安全。<br></span>" +
		"<span style=\"font-size:15px;font-family: Microsoft YaHei\"> 如果以后不想收到此类邮件，请在AI Monitor的<b>设置-显示器设置变动提醒中关闭变动提醒</b>按钮。<br></span>" +
		"<span style=\"font-size:15px;font-family: Microsoft YaHei\"> 谢谢，<br></span>" +
		"<span style=\"font-size:15px;font-family: Microsoft YaHei\"> AI Monitor团队 <br></span>"
	return desc
}

func MailForAimonitor(param string) (desc string) {
	desc = "<span style=\"font-size:15px;font-family: Microsoft YaHei\"> Dear User,<br></span>" +
		"<span style=\"font-size:15px;font-family: Microsoft YaHei\"> Our system detected that <span style=\"color: red;\"><b>" + param + "</b></span>. If it is not your operation, please check the safety of your monitor. <br></span>" +
		"<span style=\"font-size:15px;font-family: Microsoft YaHei\"> If you do not want to receive such email notifications in the future, please turn off the change reminder button in AI Monitor's Settings-Display Settings Change Reminder.<br></span>" +
		"<span style=\"font-size:15px;font-family: Microsoft YaHei\"> Best, <br></span>" +
		"<span style=\"font-size:15px;font-family: Microsoft YaHei\"> AI Monitor Team <br></span>"
	return desc
}

func SysAdminService() ISysAdminService {
	return &sysAdminServiceImpl
}
