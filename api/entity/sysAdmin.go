// 用户相关结构体
package entity

import "admin-go-api/common/util"

// 用户模型对象
type SysAdmin struct {
	//gorm.Model

	Id int `json:"id" gorm:"column:id;int;comment:'Appid'"`

	AppName string `json:"app_name" gorm:"column:AppName;varchar(64);comment:'app名称'"`

	CreateTime util.HTime `json:"create_time" gorm:"column:CreateTime;comment:'app创建时间'"`

	Description string `json:"description" gorm:"column:Description;varchar(500);comment:'app描述'"`
}

func (SysAdmin) TableName() string {
	return "app"
}

// Email对象
type Email struct {
	Id            int    `json:"id" gorm:"column:id;int;comment:'EmailId'"`
	Email         string `json:"email" gorm:"column:Email;varchar(100);comment:'email'"`
	EmailPassword string `json:"emailPassword" gorm:"column:EmailPassword;varchar(200);comment:'emailPassword'"`
	Host          string `json:"host" gorm:"column:Host;varchar(100);comment:'host'"`
}

func (Email) TableName() string {
	return "sys"
}

// 鉴权用户结构体
type JwtAdmin struct {
	Id       string `json:"id"`
	App_name string `json:"app_name"`
	Id_type  string `json:"id_type"`
}
