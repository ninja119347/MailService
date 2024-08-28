// 状态码
package result

// codes定义状态
type Codes struct {
	SUCCESS  uint
	FAILED   uint
	Message  map[uint]string
	NOAUTH   uint
	AUTHFORM uint

	LoginRequestBodyError uint
	LoginIdError          uint
	LoginUltraDataError   uint
	LoginAppidError       uint
	LoginAppnameError     uint

	MailHeaderError        uint
	MailTokenError         uint
	MailAppnameError       uint
	MailAppnameExistsError uint
	MailUsersError         uint
	MailBidError           uint
	MailTypeError          uint
	MailLanguageError      uint
	MailAppnameBidError    uint
	MailRequestBodyError   uint

	ERRMAILSEND   uint
	ERRMAILPARAMS uint
	ERRMAILVCODE  uint
	ERROK         uint
}

// ApiCode 状态码
var ApiCode = &Codes{
	SUCCESS:  200,
	FAILED:   501,
	NOAUTH:   403,
	AUTHFORM: 405,

	LoginRequestBodyError: 406,
	LoginIdError:          407,
	LoginUltraDataError:   408,
	LoginAppidError:       409,
	LoginAppnameError:     410,

	MailHeaderError:        411,
	MailTokenError:         412,
	MailAppnameError:       413,
	MailAppnameExistsError: 414,

	MailUsersError:       415,
	MailBidError:         416,
	MailTypeError:        417,
	MailLanguageError:    418,
	MailAppnameBidError:  419,
	MailRequestBodyError: 420,

	ERRMAILSEND:   801,
	ERRMAILPARAMS: 802,
	ERRMAILVCODE:  803,
	ERROK:         0,
}

func init() {
	ApiCode.Message = map[uint]string{
		ApiCode.SUCCESS:  "OK",
		ApiCode.FAILED:   "FAILED",
		ApiCode.NOAUTH:   "请求头中token为空",
		ApiCode.AUTHFORM: "请求头中token格式有误",

		// 接口错误信息模糊化
		ApiCode.LoginRequestBodyError: "invalid request body",

		ApiCode.LoginIdError:        "request param error",
		ApiCode.LoginUltraDataError: "request param error",
		ApiCode.LoginAppidError:     "request param error",
		ApiCode.LoginAppnameError:   "request param error",

		ApiCode.MailHeaderError:        "invalid header",
		ApiCode.MailTokenError:         "invalid header",
		ApiCode.MailAppnameError:       "invalid header",
		ApiCode.MailAppnameExistsError: "invalid header",

		ApiCode.MailUsersError:       "request param error",
		ApiCode.MailBidError:         "request param error",
		ApiCode.MailTypeError:        "request param error",
		ApiCode.MailLanguageError:    "request param error",
		ApiCode.MailAppnameBidError:  "request param error",
		ApiCode.MailRequestBodyError: "request param error",

		ApiCode.ERRMAILPARAMS: "param error",
	}
}

// 供外部调用
func (c *Codes) GetMessage(code uint) string {
	msg, ok := c.Message[code]
	if ok {
		return msg
	}
	return c.Message[c.FAILED]
}
