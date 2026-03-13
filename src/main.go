package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"fnproxy/config"
	"fnproxy/fnproxy"
	"fnproxy/handlers"
	"fnproxy/middleware"
	"fnproxy/security"
	"fnproxy/utils"
)

func main() {
	actionArg := flag.String("action", "", "进程控制动作：status、stop、restart")
	secureArg := flag.String("secure", "", "用于密码加密与 OAuth 解密的安全参数")
	configPathArg := flag.String("config_path", "", "用于设置配置/缓存/证书/PID 文件保存目录")
	portArg := flag.String("port", "", "设置管理端口；传数字表示 TCP 端口，传 sock 表示使用 Unix Socket")
	flag.Parse()
	actionValue := strings.TrimSpace(*actionArg)
	secureValue := strings.TrimSpace(*secureArg)
	configPathValue := strings.TrimSpace(*configPathArg)
	portValue := strings.TrimSpace(*portArg)

	if err := config.SetRuntimeBaseDir(configPathValue); err != nil {
		fmt.Printf("初始化运行目录失败: %v\n", err)
		os.Exit(1)
	}

	action, actionErr := resolveAction(actionValue, flag.Args())
	if actionErr != nil {
		fmt.Printf("解析 action 参数失败: %v\n", actionErr)
		os.Exit(1)
	}
	pidFilePath := config.RuntimePIDFilePath()
	switch action {
	case "status":
		os.Exit(printProcessStatus(pidFilePath))
	case "stop":
		pid, stopped, err := stopProcessByPIDFile(pidFilePath)
		if err != nil {
			fmt.Printf("停止程序失败: %v\n", err)
			os.Exit(1)
		}
		if !stopped {
			fmt.Printf("程序未启动，PID 文件：%s\n", pidFilePath)
			return
		}
		fmt.Printf("程序已停止，PID=%d\n", pid)
		return
	case "restart":
		pid, stopped, err := stopProcessByPIDFile(pidFilePath)
		if err != nil {
			fmt.Printf("重启前停止程序失败: %v\n", err)
			os.Exit(1)
		}
		if stopped {
			fmt.Printf("检测到已有进程，已停止旧进程 PID=%d，准备重启...\n", pid)
		} else {
			fmt.Println("未检测到运行中的旧进程，直接启动新进程。")
		}
	}

	if err := ensureSingleInstance(pidFilePath); err != nil {
		fmt.Printf("启动失败: %v\n", err)
		os.Exit(1)
	}

	secureValue = security.SetSecureSecret(secureValue)

	// 初始化配置
	cfg := config.GetManager()
	if err := config.SetRuntimeAdminTarget(portValue, cfg.GetConfig().Global.AdminPort); err != nil {
		fmt.Printf("初始化管理端监听参数失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("服务管理启动中...")
	fmt.Println("启动参数提示：可通过 -secure=\"你的密钥\" 指定密码加密与 OAuth 解密安全参数。")
	fmt.Printf("运行目录：%s\n", config.GetRuntimeBaseDir())
	if secureValue == security.DefaultSecureSecret {
		fmt.Printf("未指定 secure 参数，当前使用默认安全参数：%s。生产环境建议显式指定。\n", security.DefaultSecureSecret)
	} else {
		fmt.Println("已加载 secure 安全参数。")
	}

	// 初始化安全日志管理器
	auditLogger := security.GetAuditLogger()
	if err := auditLogger.InitStore(config.RuntimeSecurityLogCachePath()); err != nil {
		fmt.Printf("初始化安全日志存储失败: %v\n", err)
	}
	auditLogger.SetMaxEntriesFunc(func() int {
		return cfg.GetConfig().Global.MaxSecurityLogEntries
	})

	// 初始化代理服务器
	proxyServer := fnproxy.GetServer()
	proxyServer.SetSecureSecret(secureValue)
	utils.GetMonitor()
	certManager := utils.GetCertificateManager()

	// 设置HTTP路由
	mux := http.NewServeMux()

	// 管理后台OAuth登录页面（公开路径）
	mux.HandleFunc("/admin-oauth", handlers.AdminOAuthHandler)

	// 静态文件服务（已内嵌到可执行文件）需要认证
	staticHandler := newStaticFileServer()
	protectedStaticHandler := handlers.AdminPageAuthMiddleware(staticHandler)
	mux.Handle("/", protectedStaticHandler)
	mux.Handle("/static/", http.StripPrefix("/static/", protectedStaticHandler))

	// API路由
	apiMux := http.NewServeMux()

	// 认证相关
	apiMux.HandleFunc("/api/login", handlers.LoginHandler)
	apiMux.HandleFunc("/api/logout", handlers.LogoutHandler)
	apiMux.HandleFunc("/api/me", handlers.GetCurrentUserHandler)
	apiMux.HandleFunc("/api/auth/public-key", handlers.AuthPublicKeyHandler)

	// 状态
	apiMux.HandleFunc("/api/status", handlers.StatusHandler)
	apiMux.HandleFunc("/api/metrics/network-history", handlers.NetworkHistoryHandler)
	apiMux.HandleFunc("/api/metrics/listeners", handlers.ListenerStatsHandler)
	apiMux.HandleFunc("/api/metrics/services", handlers.ServiceStatsHandler)
	apiMux.HandleFunc("/api/logs/listeners/", handlers.ListenerLogsHandler)
	apiMux.HandleFunc("/api/logs/services/", handlers.ServiceLogsHandler)

	// 端口监听管理
	apiMux.HandleFunc("/api/listeners", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handlers.ListListenersHandler(w, r)
		case http.MethodPost:
			handlers.CreateListenerHandler(w, r)
		default:
			handlers.WriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	})

	apiMux.HandleFunc("/api/listeners/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path[len("/api/listeners/"):]

		// 处理 toggle 操作
		if strings.HasSuffix(path, "/toggle") {
			if r.Method == http.MethodPost {
				handlers.ToggleListenerHandler(w, r)
			} else {
				handlers.WriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
			}
			return
		}
		if strings.HasSuffix(path, "/reload") {
			if r.Method == http.MethodPost {
				handlers.ReloadListenerHandler(w, r)
			} else {
				handlers.WriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
			}
			return
		}

		switch r.Method {
		case http.MethodGet:
			// 获取单个监听器
			handlers.WriteSuccess(w, config.GetManager().GetListener(path))
		case http.MethodPut:
			handlers.UpdateListenerHandler(w, r)
		case http.MethodDelete:
			handlers.DeleteListenerHandler(w, r)
		default:
			handlers.WriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	})

	// 服务配置管理
	apiMux.HandleFunc("/api/services", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handlers.ListServicesHandler(w, r)
		case http.MethodPost:
			handlers.CreateServiceHandler(w, r)
		default:
			handlers.WriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	})

	apiMux.HandleFunc("/api/services/reorder", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			handlers.ReorderServicesHandler(w, r)
			return
		}
		handlers.WriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
	})

	apiMux.HandleFunc("/api/services/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path[len("/api/services/"):]
		if strings.HasSuffix(path, "/toggle") {
			if r.Method == http.MethodPost {
				handlers.ToggleServiceHandler(w, r)
			} else {
				handlers.WriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
			}
			return
		}

		switch r.Method {
		case http.MethodGet:
			handlers.GetServiceHandler(w, r)
		case http.MethodPut:
			handlers.UpdateServiceHandler(w, r)
		case http.MethodDelete:
			handlers.DeleteServiceHandler(w, r)
		default:
			handlers.WriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	})

	// 用户管理
	apiMux.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handlers.ListUsersHandler(w, r)
		case http.MethodPost:
			handlers.CreateUserHandler(w, r)
		default:
			handlers.WriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	})

	apiMux.HandleFunc("/api/users/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path[len("/api/users/"):]
		if strings.HasSuffix(path, "/toggle") {
			if r.Method == http.MethodPost {
				handlers.ToggleUserHandler(w, r)
			} else {
				handlers.WriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
			}
			return
		}

		switch r.Method {
		case http.MethodPut:
			handlers.UpdateUserHandler(w, r)
		case http.MethodDelete:
			handlers.DeleteUserHandler(w, r)
		default:
			handlers.WriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	})

	// 配置管理
	apiMux.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handlers.GetConfigHandler(w, r)
		case http.MethodPut:
			handlers.UpdateConfigHandler(w, r)
		default:
			handlers.WriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	})

	// 证书管理
	apiMux.HandleFunc("/api/certificates", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handlers.ListCertificatesHandler(w, r)
		case http.MethodPost:
			handlers.CreateCertificateHandler(w, r)
		default:
			handlers.WriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	})

	apiMux.HandleFunc("/api/certificates/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path[len("/api/certificates/"):]
		if strings.HasSuffix(path, "/renew") {
			if r.Method == http.MethodPost {
				handlers.RenewCertificateHandler(w, r)
			} else {
				handlers.WriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
			}
			return
		}

		switch r.Method {
		case http.MethodGet:
			handlers.GetCertificateHandler(w, r)
		case http.MethodPut:
			handlers.UpdateCertificateHandler(w, r)
		case http.MethodDelete:
			handlers.DeleteCertificateHandler(w, r)
		default:
			handlers.WriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	})

	// SSH连接管理
	apiMux.HandleFunc("/api/ssh-connections", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handlers.ListSSHConnectionsHandler(w, r)
		case http.MethodPost:
			handlers.CreateSSHConnectionHandler(w, r)
		default:
			handlers.WriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	})

	apiMux.HandleFunc("/api/ssh-connections/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path[len("/api/ssh-connections/"):]
		if strings.HasSuffix(path, "/test") {
			if r.Method == http.MethodPost {
				handlers.TestSSHConnectionHandler(w, r)
			} else {
				handlers.WriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
			}
			return
		}
		switch r.Method {
		case http.MethodGet:
			handlers.GetSSHConnectionHandler(w, r)
		case http.MethodPut:
			handlers.UpdateSSHConnectionHandler(w, r)
		case http.MethodDelete:
			handlers.DeleteSSHConnectionHandler(w, r)
		default:
			handlers.WriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	})

	apiMux.HandleFunc("/api/terminal-sessions", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handlers.ListTerminalSessionsHandler(w, r)
		case http.MethodPost:
			handlers.CreateTerminalSessionHandler(w, r)
		default:
			handlers.WriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	})

	apiMux.HandleFunc("/api/terminal-sessions/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path[len("/api/terminal-sessions/"):]
		if strings.HasSuffix(path, "/heartbeat") {
			if r.Method == http.MethodPost {
				handlers.TerminalHeartbeatHandler(w, r)
			} else {
				handlers.WriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
			}
			return
		}

		switch r.Method {
		case http.MethodDelete:
			handlers.DeleteTerminalSessionHandler(w, r)
		default:
			handlers.WriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	})

	// 安全日志
	apiMux.HandleFunc("/api/security-logs", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handlers.HandleGetSecurityLogs(w, r)
		case http.MethodDelete:
			handlers.HandleClearSecurityLogs(w, r)
		default:
			handlers.WriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	})
	apiMux.HandleFunc("/api/security-logs/stats", handlers.HandleGetSecurityLogStats)

	// 服务器重启
	apiMux.HandleFunc("/api/restart", handlers.RestartServerHandler)

	// WebSocket终端
	apiMux.HandleFunc("/ws/terminal", handlers.TerminalHandler)

	// 应用中间件
	var handler http.Handler = apiMux
	handler = middleware.AuthMiddleware(handler)
	handler = middleware.CORSMiddleware(handler)
	handler = middleware.LoggingMiddleware(handler)

	// 挂载API路由
	mux.Handle("/api/", handler)
	mux.Handle("/ws/", handler)

	// 创建HTTP服务器
	adminPort := config.GetRuntimeAdminPort(cfg.GetConfig().Global.AdminPort)
	server := &http.Server{Handler: mux}
	var (
		adminListener net.Listener
		listenErr     error
		adminEndpoint string
		socketPath    string
	)
	if config.IsRuntimeAdminSocket() {
		socketPath = config.RuntimeSocketFilePath()
		_ = os.Remove(socketPath)
		adminListener, listenErr = net.Listen("unix", socketPath)
		if listenErr != nil {
			fmt.Printf("启动管理后台失败: %v\n", listenErr)
			os.Exit(1)
		}
		adminEndpoint = "unix://" + socketPath
	} else {
		server.Addr = fmt.Sprintf(":%d", adminPort)
		adminListener, listenErr = net.Listen("tcp", server.Addr)
		if listenErr != nil {
			fmt.Printf("启动管理后台失败: %v\n", listenErr)
			os.Exit(1)
		}
		adminEndpoint = fmt.Sprintf("http://localhost:%d", adminPort)
	}

	go func() {
		fmt.Printf("管理后台启动于 %s\n", adminEndpoint)
		if err := server.Serve(adminListener); err != nil && err != http.ErrServerClosed {
			fmt.Printf("服务器错误: %v\n", err)
		}
	}()

	if err := os.MkdirAll(filepath.Dir(pidFilePath), 0755); err != nil {
		fmt.Printf("创建 PID 目录失败 [%s]: %v\n", filepath.Dir(pidFilePath), err)
	} else if err := os.WriteFile(pidFilePath, []byte(fmt.Sprintf("%d", os.Getpid())), 0644); err != nil {
		fmt.Printf("写入 PID 文件失败 [%s]: %v\n", pidFilePath, err)
	} else {
		fmt.Printf("PID 文件已写入：%s\n", pidFilePath)
	}

	if err := proxyServer.Start(); err != nil {
		fmt.Printf("部分端口启动失败，程序将继续运行: %v\n", err)
	}
	renewCtx, renewCancel := context.WithCancel(context.Background())
	certManager.StartAutoRenew(renewCtx)
	fmt.Println("代理服务器已启动")

	// 优雅关闭
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	<-quit
	fmt.Println("\n正在关闭服务器...")
	renewCancel()

	// 关闭终端会话
	handlers.CloseAllSessions()

	// 停止代理服务器
	if err := proxyServer.Stop(); err != nil {
		fmt.Printf("停止代理服务器失败: %v\n", err)
	}

	// 关闭HTTP服务器
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		fmt.Printf("服务器关闭失败: %v\n", err)
	}
	if socketPath != "" {
		if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
			fmt.Printf("删除 unix socket 文件失败 [%s]: %v\n", socketPath, err)
		}
	}
	if err := os.Remove(pidFilePath); err != nil && !os.IsNotExist(err) {
		fmt.Printf("删除 PID 文件失败 [%s]: %v\n", pidFilePath, err)
	}

	fmt.Println("服务器已关闭")
}
