package main

import (
	"bufio"
	"encoding/base64"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"github.com/tredoe/osutil/user/crypt/apr1_crypt"
)

// 读取 htpasswd 文件
func loadHtpasswd(filePath string) (map[string][]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	users := make(map[string][]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		username, hash := parts[0], parts[1]
		users[username] = append(users[username], hash)
	}
	return users, scanner.Err()
}

// 认证用户名和密码
func verifyPassword(password, hash string) bool {
	crypt := apr1_crypt.New()
	err := crypt.Verify(hash, []byte(password))
	return err == nil
}

// Basic Auth 中间件
func basicAuthMiddleware(users map[string][]string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userAgent := r.Header.Get("User-Agent")
		//	log.Println(userAgent)
		if !strings.Contains(userAgent, "Edg") {
			next.ServeHTTP(w, r) // 非 Edg 浏览器直接放行
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted Area"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// 解析 Basic Auth
		authParts := strings.SplitN(authHeader, " ", 2)
		if len(authParts) != 2 || authParts[0] != "Basic" {
			http.Error(w, "Invalid Authorization Header", http.StatusUnauthorized)
			return
		}

		decoded, err := base64.StdEncoding.DecodeString(authParts[1])
		if err != nil {
			http.Error(w, "Invalid Base64 Encoding", http.StatusUnauthorized)
			return
		}

		// 提取 `username:password`
		credentials := strings.SplitN(string(decoded), ":", 2)
		if len(credentials) != 2 {
			http.Error(w, "Invalid Credentials Format", http.StatusUnauthorized)
			return
		}
		username, password := credentials[0], credentials[1]

		// 认证
		if hashes, exists := users[username]; exists {
			for _, hash := range hashes {
				if verifyPassword(password, hash) {
					next.ServeHTTP(w, r)
					return
				}
			}
		}

		// 认证失败
		w.Header().Set("WWW-Authenticate", `Basic realm="Restricted Area"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})
}

func main() {
	// 读取 `.htpasswd`
	users, err := loadHtpasswd(".htpasswd")
	if err != nil {
		log.Fatalf("Failed to load htpasswd file: %v", err)
	}

	// 配置反向代理到 127.0.0.1:9099
	target, _ := url.Parse("http://127.0.0.1:9099")
	proxy := httputil.NewSingleHostReverseProxy(target)

	// 启动服务器
	server := &http.Server{
		Addr:    ":8080",
		Handler: basicAuthMiddleware(users, proxy),
	}

	log.Println("Starting server on :8080, proxying to 127.0.0.1:9099")
	log.Fatal(server.ListenAndServe())
}
