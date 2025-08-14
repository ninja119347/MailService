// 通用访问结构
package result

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// 消息结构体
type Result struct {
	ErrCode int         `json:"err_code"` //状态码
	ErrMsg  string      `json:"err_msg"`  //提示信息
	Data    interface{} `json:"data"`     //返回的数据
}

// 邮件返回结构体
type EmailResponse struct {
	ErrCode int    `json:"err_code"`
	ErrMsg  string `json:"err_msg"`
	Code    string `json:"code"`
}

// 返回成功
func Success(c *gin.Context, data interface{}) {
	if data == nil {
		data = gin.H{}
	}
	res := Result{}
	res.ErrCode = int(ApiCode.SUCCESS)
	res.ErrMsg = ApiCode.GetMessage(ApiCode.SUCCESS)
	res.Data = data
	c.JSON(http.StatusOK, res)
}

// 返回失败
func Failed(c *gin.Context, code uint, msg string) {
	res := Result{}
	res.ErrCode = int(code)
	res.ErrMsg = msg
	res.Data = gin.H{}
	c.JSON(http.StatusOK, res)
}

// 返回成功
func SendSuccess(c *gin.Context) {
	res := EmailResponse{}
	res.ErrCode = int(ApiCode.SUCCESS)
	res.ErrMsg = ApiCode.GetMessage(ApiCode.SUCCESS)
	res.Code = ""
	c.JSON(http.StatusOK, res)
}
func SendSuccessWithCode(c *gin.Context, code string) {
	res := EmailResponse{}
	res.ErrCode = int(ApiCode.SUCCESS)
	res.ErrMsg = ApiCode.GetMessage(ApiCode.SUCCESS)
	res.Code = code
	c.JSON(http.StatusOK, res)
}

// 返回失败
func SendFailed(c *gin.Context, code uint, msg string) {
	res := EmailResponse{}
	res.ErrCode = int(code)
	res.ErrMsg = msg
	res.Code = ""
	c.JSON(http.StatusOK, res)
}
