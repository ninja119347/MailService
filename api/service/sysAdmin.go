// 用户服务层
package service

import (
	"admin-go-api/api/dao"
	"admin-go-api/api/dto"
	"admin-go-api/api/entity"
	"admin-go-api/common/constant"
	"admin-go-api/common/result"
	"admin-go-api/common/util"
	"admin-go-api/pkg/jwt"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/gotomicro/ego/core/elog"
	gomail "gopkg.in/gomail.v2"
	"log"
	"strconv"
	"strings"
	"time"
	"unicode"
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
	//err := validator.New().Struct(dto)
	err := util.ValidateStruct(&dto)
	//防止Sql注入
	//valid := util.ValidateStruct(&dto)
	//if valid != nil {
	//	result.Failed(c, uint(result.ApiCode.LoginAppnameError), result.ApiCode.GetMessage(result.ApiCode.LoginAppnameError))
	//	return
	//}
	if err != nil {
		result.Failed(c, uint(result.ApiCode.LoginRequestBodyError), result.ApiCode.GetMessage(result.ApiCode.LoginRequestBodyError))
		return
	}

	//校验appId
	if dto.Id != "223" {
		result.Failed(c, uint(result.ApiCode.LoginIdError), result.ApiCode.GetMessage(result.ApiCode.LoginIdError))
		return
	}
	//校验时间是否超时
	nowTime := time.Now()
	if int64(dto.UltraData) < (nowTime.Unix()) {
		result.Failed(c, uint(result.ApiCode.LoginUltraDataError), result.ApiCode.GetMessage(result.ApiCode.LoginUltraDataError))
		return
	}
	//校验appName
	appName, _ := dao.CheckAppNameExists(dto.AppName)
	if !appName {
		result.Failed(c, uint(result.ApiCode.LoginAppnameError), result.ApiCode.GetMessage(result.ApiCode.LoginAppnameError))
		return
	}
	// 校验appid
	app_id := dto.Id + dto.AppName + strconv.Itoa(int(dto.UltraData)) + dao.DEFAULT_KEY
	if dto.AppName == "uniupdate" {
		app_id = dto.Id + dto.AppName + strconv.Itoa(int(dto.UltraData)) + dao.UNIUPDATE_KEY
	} else if dto.AppName == "aimonitor" {
		app_id = dto.Id + dto.AppName + strconv.Itoa(int(dto.UltraData)) + dao.AIMONITOR_KEY
	} else if dto.AppName == "sign" {
		app_id = dto.Id + dto.AppName + strconv.Itoa(int(dto.UltraData)) + dao.SIGN_KEY
	} else if dto.AppName == "autobuild" {
		app_id = dto.Id + dto.AppName + strconv.Itoa(int(dto.UltraData)) + dao.AUTOBUILD_KEY
		// 在 Login 函数的 key 验证部分添加
	} else if dto.AppName == "ilfd_s2" {
		app_id = dto.Id + dto.AppName + strconv.Itoa(int(dto.UltraData)) + dao.ILFD_S2_KEY
	}

	message := []byte(app_id)
	hash := sha512.New()
	hash.Write(message)
	bytes := hash.Sum(nil)
	hashCode := hex.EncodeToString(bytes)
	if strings.ToUpper(dto.AppId) != strings.ToUpper(hashCode) {
		fmt.Println("app_id: " + strings.ToUpper(hashCode))
		result.Failed(c, uint(result.ApiCode.LoginAppidError), result.ApiCode.GetMessage(result.ApiCode.LoginAppidError))
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
	//util.TestEncryptDecrypt()
	//err := validator.New().Struct(dto)
	err := util.ValidateStruct(&dto)
	if err != nil {
		result.SendFailed(c, uint(result.ApiCode.MailRequestBodyError), result.ApiCode.GetMessage(result.ApiCode.MailRequestBodyError))
		return
	}
	u, exists := c.Get(constant.Claims)
	claims := u.(*entity.JwtAdmin)
	if !exists {
		result.SendFailed(c, result.ApiCode.MailContexError, result.ApiCode.GetMessage(result.ApiCode.MailContexError))
		return
	}
	// ==========================================================

	if dto.Users == nil {
		result.SendFailed(c, result.ApiCode.MailUsersError, result.ApiCode.GetMessage(result.ApiCode.MailUsersError))
		return
	}

	if dto.Bid != "UPW" && dto.Bid != "APW" && dto.Bid != "SIGN" && dto.Bid != "ABC" && dto.Bid != "SPW" {
		result.SendFailed(c, result.ApiCode.MailBidError, result.ApiCode.GetMessage(result.ApiCode.MailBidError))
		return
	}

	if dto.Data.Type != "1" && dto.Data.Type != "2" && dto.Data.Type != "3" && dto.Data.Type != "4" {
		result.SendFailed(c, result.ApiCode.MailTypeError, result.ApiCode.GetMessage(result.ApiCode.MailTypeError))
		return
	}

	if dto.Data.Language == "" {
		result.SendFailed(c, result.ApiCode.MailLanguageError, result.ApiCode.GetMessage(result.ApiCode.MailLanguageError))
		return
	}

	if claims.App_name == "uniupdate" && dto.Bid != "UPW" {
		result.SendFailed(c, result.ApiCode.MailAppnameBidError, result.ApiCode.GetMessage(result.ApiCode.MailAppnameBidError))
		return
	}

	if claims.App_name == "aimonitor" && dto.Bid != "APW" {
		result.SendFailed(c, result.ApiCode.MailAppnameBidError, result.ApiCode.GetMessage(result.ApiCode.MailAppnameBidError))
		return
	}

	if claims.App_name == "sign" && dto.Bid != "SIGN" {
		result.SendFailed(c, result.ApiCode.MailAppnameBidError, result.ApiCode.GetMessage(result.ApiCode.MailAppnameBidError))
		return
	}

	if claims.App_name == "autobuild" && dto.Bid != "ABC" {
		result.SendFailed(c, result.ApiCode.MailAppnameBidError, result.ApiCode.GetMessage(result.ApiCode.MailAppnameBidError))
		return
	}
	// 添加 ilfd_s2 应用的业务类型验证
	if claims.App_name == "ilfd_s2" && dto.Bid != "SPW" {
		result.SendFailed(c, result.ApiCode.MailAppnameBidError, result.ApiCode.GetMessage(result.ApiCode.MailAppnameBidError))
		return
	}
	//发送邮件
	param_bid := dto.Bid
	param_type := dto.Data.Type
	param_language := dto.Data.Language
	param_content := dto.Data.Content

	title := ""
	desc := ""
	var vcode string
	if param_bid == "UPW" {
		if param_type == "3" {
			if param_language == "zh-CN" {
				title = "Uniupdate Cloud 账户激活"
				desc = MailForUniupdateActivateCN(string(param_content))
			} else {
				title = "Uniupdate Cloud account activate"
				desc = MailForUniupdateActivate(string(param_content))
			}
		} else if param_type == "4" {
			if param_language == "zh-CN" {
				title = "Uniupdate Cloud-您有新的请求待审批"
				desc = MailForUniupdateApplicationCN(string(param_content))
			} else {
				title = "Uniupdate Cloud: You have a new request for approval"
				desc = MailForUniupdatApplication(string(param_content))
			}
		}

		var param_password []byte
		if param_type == "1" || param_type == "2" {
			ASE_KEY := "pzy0123456789pzy"
			blockSize := 16
			tool := util.NewAesTool(ASE_KEY, blockSize)
			if len(param_content)%4 != 0 || param_content == "" {
				result.SendFailed(c, result.ApiCode.MailDecryptError, result.ApiCode.GetMessage(result.ApiCode.MailDecryptError))
				return
			}
			encryptContent, _ := base64.StdEncoding.DecodeString(param_content)
			param_password, _ = tool.Decrypt([]byte(encryptContent))

			//判断非法字符
			for _, char := range string(param_password) {
				if !unicode.IsPrint(rune(char)) && char != 0 {
					result.SendFailed(c, result.ApiCode.MailDecryptError, result.ApiCode.GetMessage(result.ApiCode.MailDecryptError))
					return
				}
			}
		}

		if param_type == "1" {
			if param_language == "zh-CN" {
				title = "Uniupdate Cloud 账户创建"
				desc = MailForUniupdateCreateCN(string(param_password))
			} else {
				title = "Uniupdate Cloud account creation"
				desc = MailForUniupdatCreate(string(param_password))
			}
		} else if param_type == "2" {
			if param_language == "zh-CN" {
				title = "Uniupdate Cloud 密码重置"
				desc = MailForUniupdateResetCN(string(param_password))
			} else {
				title = "Uniupdate Cloud password reset"
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
	} else if param_bid == "SIGN" {
		if param_type == "1" {
			if param_language == "zh-CN" {
				title = "Sign-您有新的APK签名申请待审批"
				desc = MailForSignRequestCN(string(param_content))
			} else {
				title = "Sign-You have a new APK signing request pending approval"
				desc = MailForSignRequest(string(param_content))
			}
		} else if param_type == "2" {
			if param_language == "zh-CN" {
				title = "Sign-您的APK签名申请已审批"
				desc = MailForApprovedCN(string(param_content))
			} else {
				title = "Uniupdate Cloud: You have a new request for approval"
				desc = MailForApproved(string(param_content))
			}
		}
	} else if param_bid == "ABC" {
		if param_type == "1" {
			//编译成功
			if param_language == "zh-CN" {
				title = "AutoBuild-编译成功"
				desc = MailForAutoBuildSuccessCN(param_content)
			} else {
				title = "AutoBuild-Compile success"
				desc = MailForAutoBuildSuccess(param_content)
			}
		} else if param_type == "2" {
			//编译失败
			if param_language == "zh-CN" {
				title = "AutoBuild-编译失败"
				desc = MailForAutoBuildFailCN(param_content)
			} else {
				title = "AutoBuild-Compile failed"
				desc = MailForAutoBuildFail(param_content)
			}
		}
	} else if param_bid == "SPW" {
		vcode, err = util.Generate6DigitCode()
		if err != nil {
			fmt.Println("生成验证码出错:", err)
			return
		}
		if param_type == "1" {
			if param_language == "zh-CN" {
				title = "单次使用代码"
				desc = MailForIlfdEmailVerifyCN(vcode)
			} else {
				title = "Your single-use code"
				desc = MailForIlfdEmailVerify(vcode)
			}
		} else if param_type == "2" {
			if param_language == "zh-CN" {
				title = "iLFD 密码重置"
				desc = MailForIlfdPasswordResetCN(vcode)
			} else {
				title = "iLFD password reset"
				desc = MailForIlfdPasswordReset(vcode)

			}
		}
	}
	if desc == "Error parsing JSON" {
		result.SendFailed(c, result.ApiCode.ERRMAILJSON, result.ApiCode.GetMessage(result.ApiCode.ERRMAILJSON))
	}

	if title != "" && desc != "" {
		if SendMailApi(dto.Users, title, desc) {
			if dto.Bid == "SPW" {
				result.SendSuccessWithCode(c, vcode)
				return
			}
			result.SendSuccess(c)
		} else {
			result.SendFailed(c, result.ApiCode.ERRMAILSEND, result.ApiCode.GetMessage(result.ApiCode.ERRMAILSEND))
		}
	} else {
		result.SendFailed(c, result.ApiCode.ERRMAILSEND, result.ApiCode.GetMessage(result.ApiCode.ERRMAILSEND))
	}
}

func SendMailApi(to []string, title, desc string) bool {
	for _, user := range to {
		if !util.EmailIsValid(user) {
			return false
		}
	}

	err := sendMailMass(to, title, desc)
	if err != nil {
		return false
	}
	return true
}

func sendMailMass(to []string, title, message string) error {
	//var userId int
	//1->net 2->com
	mail, err := dao.GetEmailInfo()
	if err != nil {
		elog.Error(err.Error())
		return err
	}
	m := gomail.NewMessage()
	// Email Host EmailPassword sys
	//m.SetHeader(`From`, "ilfdadmin@smartdisplay.lenovo.com")

	m.SetHeader(`From`, mail.Email)
	m.SetHeader(`To`, to...)
	m.SetHeader(`Subject`, title)
	m.SetBody("text/html", message)
	port, _ := strconv.Atoi(dao.MAIL_PORT)
	d := gomail.NewDialer(mail.Host, port, mail.Email, mail.EmailPassword)
	fmt.Println("mail.port: " + strconv.Itoa(port))
	//d := gomail.NewDialer(mail.Host, 465, "visualsota@smartdisplay.lenovo.net", "LeOtVi8117")
	// 修改TLSconfig "visualsota@smartdisplay.lenovo.net" "MailTest123456"
	d.TLSConfig = &tls.Config{InsecureSkipVerify: true}
	if err1 := d.DialAndSend(m); err1 != nil {
		elog.Error(err1.Error())
		return err1
	}
	return nil
}

func MailForUniupdateCreateCN(param string) (desc string) {
	desc = "<span style=\"font-size:20px;font-family: Microsoft YaHei\"> 亲爱的联想Uniupdate Cloud用户，我们已为您创建了该邮箱的账户。 <br></span>" +
		"<span style=\"font-size:20px;font-family: Microsoft YaHei\"> 您的初始密码为：<b>" + param + " </b><br></span>" +
		"<span style=\"font-size:20px;font-family: Microsoft YaHei\"> 请在登录后立即修改密码，谢谢！<br></span>"
	return desc
}

func MailForUniupdatCreate(param string) (desc string) {
	desc = "<span style=\"font-size:20px;font-family: Microsoft YaHei\"> Dear Lenovo Uniupdate Cloud users, we have created an account for you for this mailbox. <br></span>" +
		"<span style=\"font-size:20px;font-family: Microsoft YaHei\"> Your initial password is: <b>" + param + " </b><br></span>" +
		"<span style=\"font-size:20px;font-family: Microsoft YaHei\"> Please change your password immediately after login, thanks!<br></span>"
	return desc
}

func MailForUniupdateResetCN(param string) (desc string) {
	desc = "<span style=\"font-size:20px;font-family: Microsoft YaHei\"> 亲爱的联想Uniupdate Cloud用户，我们收到了您重置密码的申请。<br></span>" +
		"<span style=\"font-size:20px;font-family: Microsoft YaHei\"> 您的临时密码为：<b>" + param + " </b><br></span>" +
		"<span style=\"font-size:20px;font-family: Microsoft YaHei\"> 请在登录后立即修改密码，谢谢！<br></span>"
	return desc
}

func MailForUniupdatReset(param string) (desc string) {
	desc = "<span style=\"font-size:20px;font-family: Microsoft YaHei\"> Dear Lenovo Uniupdate Cloud users, we have received your request to reset your password. <br></span>" +
		"<span style=\"font-size:20px;font-family: Microsoft YaHei\"> Your temporary password is: <b>" + param + " </b><br></span>" +
		"<span style=\"font-size:20px;font-family: Microsoft YaHei\"> Please change your password immediately after login, thanks!<br></span>"
	return desc
}

func MailForUniupdateActivateCN(param string) (desc string) {
	desc = "<span style=\"font-size:20px;font-family: Microsoft YaHei\"> 尊敬的用户，管理员正在为您开通 [Uniupdate Cloud] 账户。<br></span>" +
		"<span style=\"font-size:20px;font-family: Microsoft YaHei\"> 为了确保您的账户安全，请通过点击以下链接激活您的账户：【" + "<a href=\"" + param + "\">" + param + "</a>" + "】<br></span>" +
		"<span style=\"font-size:20px;font-family: Microsoft YaHei\"> 请注意，此链接将在半个小时内有效。如果超过半个小时未激活，您需要联系管理员重新发送激活邮件。<br></span>"
	return desc
}

func MailForUniupdateActivate(param string) (desc string) {
	desc = "<span style=\"font-size:20px;font-family: Microsoft YaHei\"> Dear user, the administrator is in the process of opening a [Uniupdate Cloud] account for you.<br></span>" +
		"<span style=\"font-size:20px;font-family: Microsoft YaHei\"> To ensure the security of your account, please activate your account by clicking the following link:【" + "<a href=\"" + param + "\">" + param + "</a>" + "】<br></span>" +
		"<span style=\"font-size:20px;font-family: Microsoft YaHei\"> Please note that this link will be active for half an hour. If it is not activated for more than half an hour, you will need to contact the administrator to resend the activation email.<br></span>"
	return desc
}

func MailForUniupdateApplicationCN(param string) (desc string) {
	var result map[string]interface{}

	// 解析 JSON 字符串
	err := json.Unmarshal([]byte(param), &result)
	if err != nil {
		log.Fatalf("Error parsing JSON: %v", err)
		desc = "Error parsing JSON"
		return desc
	}

	var submitter string = result["submitter"].(string)
	var modelName string = result["modelName"].(string)
	var versionCode string = result["versionCode"].(string)
	var url string = result["url"].(string)

	if versionCode != "" {
		versionCode = "版本号【" + versionCode + "】，"
	}

	desc = "<span style=\"font-size:20px;font-family: Microsoft YaHei\"> 管理员您好：<br></span>" +
		"<span style=\"font-size:20px;font-family: Microsoft YaHei\"> 【" + submitter + "】提交了：机型【" + modelName + "】，" + versionCode + "请点击链接去系统审批中进行审批：【" + "<a href=\"" + url + "\">" + url + "</a>" + "】<br></span>"
	return desc
}

func MailForSignRequestCN(param string) (desc string) {
	var result map[string]interface{}

	// 解析 JSON 字符串
	err := json.Unmarshal([]byte(param), &result)
	if err != nil {
		log.Fatalf("Error parsing JSON: %v", err)
		desc = "Error parsing JSON"
		return desc
	}

	var id string = result["id"].(string)
	var applicant string = result["applicant"].(string)
	var filename string = result["filename"].(string)
	var mt string = result["mt"].(string)
	var description string = result["description"].(string)
	var url string = result["url"].(string)

	desc = "<span style=\"font-size:25px;font-family: Microsoft YaHei\"> 您有新的APK签名申请待审批, 签名申请详情:  <br></span>" +
		"<span style=\"font-size:20px;font-family: Microsoft YaHei\"> Application ID: <b>" + id + " </b><br></span>" +
		"<span style=\"font-size:20px;font-family: Microsoft YaHei\"> Applicant: <b>" + applicant + " </b><br></span>" +
		"<span style=\"font-size:20px;font-family: Microsoft YaHei\"> File Name: <b>" + filename + " </b><br></span>" +
		"<span style=\"font-size:20px;font-family: Microsoft YaHei\"> Machine Types: <b>" + mt + " </b><br></span>" +
		"<span style=\"font-size:20px;font-family: Microsoft YaHei\"> Description: <b>" + description + " </b><br></span>" +
		"<span style=\"font-size:20px;font-family: Microsoft YaHei\"> 请点击 " + "<a href=\"" + url + "\">" + url + "</a>" + " 前往审批。</span>"
	return desc
}

func MailForSignRequest(param string) (desc string) {
	var result map[string]interface{}

	// 解析 JSON 字符串
	err := json.Unmarshal([]byte(param), &result)
	if err != nil {
		log.Fatalf("Error parsing JSON: %v", err)
		desc = "Error parsing JSON"
		return desc
	}

	var id string = result["id"].(string)
	var applicant string = result["applicant"].(string)
	var filename string = result["filename"].(string)
	var mt string = result["mt"].(string)
	var description string = result["description"].(string)
	var url string = result["url"].(string)

	desc = "<span style=\"font-size:25px;font-family: Microsoft YaHei\"> You have a new APK sign request pending approval, the sign request info:  <br></span>" +
		"<span style=\"font-size:20px;font-family: Microsoft YaHei\"> Application ID: <b>" + id + " </b><br></span>" +
		"<span style=\"font-size:20px;font-family: Microsoft YaHei\"> Applicant: <b>" + applicant + " </b><br></span>" +
		"<span style=\"font-size:20px;font-family: Microsoft YaHei\"> File Name: <b>" + filename + " </b><br></span>" +
		"<span style=\"font-size:20px;font-family: Microsoft YaHei\"> Machine Types: <b>" + mt + " </b><br></span>" +
		"<span style=\"font-size:20px;font-family: Microsoft YaHei\"> Description: <b>" + description + " </b><br></span>" +
		"<span style=\"font-size:20px;font-family: Microsoft YaHei\"> Please click " + "<a href=\"" + url + "\">" + url + "</a>" + " to go to approval.</span>"
	return desc
}

func MailForApprovedCN(param string) (desc string) {
	var result map[string]interface{}

	// 解析 JSON 字符串
	err := json.Unmarshal([]byte(param), &result)
	if err != nil {
		log.Fatalf("Error parsing JSON: %v", err)
		desc = "Error parsing JSON"
		return desc
	}

	var id string = result["id"].(string)
	var approver string = result["approver"].(string)
	var filename string = result["filename"].(string)
	var mt string = result["mt"].(string)
	var status string = result["status"].(string)
	var comment string = result["comment"].(string)
	var url string = result["url"].(string)

	desc = "<span style=\"font-size:25px;font-family: Microsoft YaHei\"> 您的APK签名申请已审批, 审批结果详情:  <br></span>" +
		"<span style=\"font-size:20px;font-family: Microsoft YaHei\"> Application ID: <b>" + id + " </b><br></span>" +
		"<span style=\"font-size:20px;font-family: Microsoft YaHei\"> Approver: <b>" + approver + " </b><br></span>" +
		"<span style=\"font-size:20px;font-family: Microsoft YaHei\"> File Name: <b>" + filename + " </b><br></span>" +
		"<span style=\"font-size:20px;font-family: Microsoft YaHei\"> Machine Types: <b>" + mt + " </b><br></span>" +
		"<span style=\"font-size:20px;font-family: Microsoft YaHei\"> Result: <b>" + status + " </b><br></span>" +
		"<span style=\"font-size:20px;font-family: Microsoft YaHei\"> Comment: <b>" + comment + " </b><br></span>" +
		"<span style=\"font-size:20px;font-family: Microsoft YaHei\"> 请点击 " + "<a href=\"" + url + "\">" + url + "</a>" + " 前往查看详情。</span>"
	return desc
}

func MailForApproved(param string) (desc string) {
	var result map[string]interface{}

	// 解析 JSON 字符串
	err := json.Unmarshal([]byte(param), &result)
	if err != nil {
		log.Fatalf("Error parsing JSON: %v", err)
		desc = "Error parsing JSON"
		return desc
	}

	var id string = result["id"].(string)
	var approver string = result["approver"].(string)
	var filename string = result["filename"].(string)
	var mt string = result["mt"].(string)
	var status string = result["result"].(string)
	var comment string = result["comment"].(string)
	var url string = result["url"].(string)

	desc = "<span style=\"font-size:25px;font-family: Microsoft YaHei\"> Your APK sign request has been approved, the approval result info:  <br></span>" +
		"<span style=\"font-size:20px;font-family: Microsoft YaHei\"> Application ID: <b>" + id + " </b><br></span>" +
		"<span style=\"font-size:20px;font-family: Microsoft YaHei\"> Approver: <b>" + approver + " </b><br></span>" +
		"<span style=\"font-size:20px;font-family: Microsoft YaHei\"> File Name: <b>" + filename + " </b><br></span>" +
		"<span style=\"font-size:20px;font-family: Microsoft YaHei\"> Machine Types: <b>" + mt + " </b><br></span>" +
		"<span style=\"font-size:20px;font-family: Microsoft YaHei\"> Result: <b>" + status + " </b><br></span>" +
		"<span style=\"font-size:20px;font-family: Microsoft YaHei\"> Comment: <b>" + comment + " </b><br></span>" +
		"<span style=\"font-size:20px;font-family: Microsoft YaHei\"> Please click " + "<a href=\"" + url + "\">" + url + "</a>" + " to check detail.</span>"
	return desc
}

func MailForUniupdatApplication(param string) (desc string) {
	var result map[string]interface{}

	// 解析 JSON 字符串
	err := json.Unmarshal([]byte(param), &result)
	if err != nil {
		log.Fatalf("Error parsing JSON: %v", err)
		desc = "Error parsing JSON"
		return desc
	}

	var submitter string = result["submitter"].(string)
	var modelName string = result["modelName"].(string)
	var versionCode string = result["versionCode"].(string)
	var url string = result["url"].(string)

	if versionCode != "" {
		versionCode = "version number【" + versionCode + "】，"
	}

	desc = "<span style=\"font-size:20px;font-family: Microsoft YaHei\"> Hello administrator: <br></span>" +
		"<span style=\"font-size:20px;font-family: Microsoft YaHei\"> 【" + submitter + "】submitted: model【" + modelName + "】，" + versionCode + " please click on the link to go to approval:【" + "<a href=\"" + url + "\">" + url + "</a>" + "】<br></span>"
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

func MailForAutoBuildSuccessCN(param string) (desc string) {
	desc = "<span style=\"font-size:15px;font-family: Microsoft YaHei\"> 您的编译任务已完成，编译成功。<br></span>" +
		"<span style=\"font-size:15px;font-family: Microsoft YaHei\"> 编译结果：【" + param + "】<br></span>"
	return desc
}

func MailForAutoBuildSuccess(param string) (desc string) {
	desc = "<span style=\"font-size:15px;font-family: Microsoft YaHei\"> Your compilation task has been completed and compiled successfully.<br></span>" +
		"<span style=\"font-size:15px;font-family: Microsoft YaHei\"> Compilation result:【" + param + "】<br></span>"
	return desc
}

func MailForAutoBuildFailCN(param string) (desc string) {
	desc = "<span style=\"font-size:15px;font-family: Microsoft YaHei\"> 您的编译任务已完成，编译失败。<br></span>" +
		"<span style=\"font-size:15px;font-family: Microsoft YaHei\"> 编译结果：【" + param + "】<br></span>"
	return desc
}

func MailForAutoBuildFail(param string) (desc string) {
	desc = "<span style=\"font-size:15px;font-family: Microsoft YaHei\"> Your compilation task has been completed and compiled failed.<br></span>" +
		"<span style=\"font-size:15px;font-family: Microsoft YaHei\"> Compilation result:【" + param + "】<br></span>"
	return desc
}
func MailForIlfdEmailVerifyCN(vcode string) (desc string) {
	desc = "<span style=\"font-size:25px;font-family: Microsoft YaHei\"> 亲爱的联想iLFD用户，我们收到了您设置邮箱的请求。<br></span>" +
		"<span style=\"font-size:25px;font-family: Microsoft YaHei\"> 请输入一次性使用代码：" + vcode + "<br></span>" +
		"<span style=\"font-size:25px;font-family: Microsoft YaHei\"> 谢谢！ <br></span>"
	return desc
}
func MailForIlfdEmailVerify(vcode string) (desc string) {
	desc = "<span style=\"font-size:25px;font-family: Microsoft YaHei\"> Dear Lenovo iLFD users, we have received your request to set up your mailbox.<br></span>" +
		"<span style=\"font-size:25px;font-family: Microsoft YaHei\"> Please enter the one-time use code: " + vcode + "<br></span>" +
		"<span style=\"font-size:25px;font-family: Microsoft YaHei\"> Thanks! <br></span>"
	return desc
}

func MailForIlfdPasswordResetCN(vcode string) (desc string) {
	desc = "<span style=\"font-size:25px;font-family: Microsoft YaHei\"> 尊敬的联想iLFD用户，我们收到了您重置 iLFD 密码的申请。<br></span>" +
		"<span style=\"font-size:25px;font-family: Microsoft YaHei\"> 请输入重置代码：" + vcode + "<br></span>" +
		"<span style=\"font-size:25px;font-family: Microsoft YaHei\"> 谢谢！ <br></span>"
	return desc
}

func MailForIlfdPasswordReset(vcode string) (desc string) {
	desc = "<span style=\"font-size:25px;font-family: Microsoft YaHei\"> Dear Lenovo iLFD users, we have received your request to reset your iLFD password.<br></span>" +
		"<span style=\"font-size:25px;font-family: Microsoft YaHei\"> Please enter the reset code: " + vcode + "<br></span>" +
		"<span style=\"font-size:25px;font-family: Microsoft YaHei\"> Thanks! <br></span>"
	return desc
}

func SysAdminService() ISysAdminService {
	return &sysAdminServiceImpl
}
