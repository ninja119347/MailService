package main

import (
	"log"
	"net/http"
)

func main() {
	// 明确注册一个根路由
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello https\n"))
	})

	log.Println("启动 HTTPS :2002")
	err := http.ListenAndServeTLS(":2002", "cert.pem", "key.pem", nil)
	if err != nil {
		log.Fatalf("TLS 启动失败: %v", err)
	}
}
