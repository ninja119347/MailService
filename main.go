// 启动程序
package main

import (
	"admin-go-api/common/config"
	_ "admin-go-api/docs"
	// "admin-go-api/pkg/db"
	"admin-go-api/pkg/log"
	"admin-go-api/pkg/redis"
	"admin-go-api/router"
	"context"
	"fmt"
	"crypto/tls"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"net/http"
	"os"
	"os/signal"
	"time"
)

// @title lenovo-email
// @version 1.0
// @description 后台管理系统API接口文档
// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name Authorization
var validate *validator.Validate

func main() {
	fmt.Println("hello world")
	logger := log.Log()
	gin.SetMode(config.Config.Server.Model)

	// 初始化路由
	r := router.InitRouter()

	// 加 HSTS 头的中间件（只在 HTTPS 下加）
	r.Use(func(c *gin.Context) {
		if c.Request.TLS != nil {
			c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		}
		c.Next()
	})

	srv := &http.Server{
		Addr:    config.Config.Server.Address, // 比如 ":2002"
		Handler: r,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	// 启动 HTTPS 服务
	go func() {
		logger.Info("Starting HTTPS on " + config.Config.Server.Address)
		if err := srv.ListenAndServeTLS("cert.pem", "key.pem"); err != nil && err != http.ErrServerClosed {
			logger.Info(fmt.Sprintf("listen: %s\n", err))
		}
	}()

	// 等待中断信号
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit
	logger.Info("Shutdown Server ...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logger.Info(fmt.Sprintf("Server Shutdown: %v", err))
	}
	logger.Info("Server exiting")
}

// 初始化连接
func init() {
	//mysql
	db.SetupDBLink() // ← 注释掉这行，跳过数据库初始化
	//redis
	redis.SetupRedisDB()
}
