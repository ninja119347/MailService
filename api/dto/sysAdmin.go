package dto

import "time"

// 登陆对象
type LoginDto struct {
	AppName   string `json:"app_name" validate:"required"`   //app名称
	Id        string `json:"id" validate:"required"`         //固定值223
	IdType    string `json:"id_type" validate:"required"`    //Id类型固定值uuid
	UltraData int64  `json:"ultra_data" validate:"required"` //附加数据
	AppId     string `json:"app_id" validate:"required"`     //AppId
}

// 发送对象
type SendDto struct {
	Users []string `json:"users" validate:"required,dive,email"` //目标用户邮箱
	Bid   string   `json:"bid" validate:"required"`              //业务大类
	Data  Data     `json:"data" validate:"required"`             //数据封装

}

type Data struct {
	Type     string `json:"type" validate:"required"`     //业务小类型
	Language string `json:"language" validate:"required"` //邮件语言
	Content  string `json:"content"`                      //自定义内容
}

// 检查 UtraData 是否过期的函数
func (dto *LoginDto) IsUtraDataExpired() bool {
	currentTimestamp := time.Now().Unix()
	return currentTimestamp > dto.UltraData
}
