package fnproxy

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"fnproxy/config"
	"fnproxy/models"
	"fnproxy/pkg/oauth"
	"fnproxy/security"
	"fnproxy/utils"

	"github.com/gorilla/websocket"
)

// Server 代理服务器管理
type Server struct {
	mu                sync.RWMutex
	ctx               context.Context
	cancel            context.CancelFunc
	servers           map[string]*http.Server
	routes            map[string][]serviceRoute // 动态路由表，按监听器ID分组
	listeners         map[string]models.PortListener // 监听器配置缓存
	proxies           map[string]*httputil.ReverseProxy
	lastGood          map[string]listenerSnapshot
	oauthPrivateKey   *rsa.PrivateKey
	oauthPublicKeyPEM string
}

type serviceRoute struct {
	service models.ServiceConfig
	handler http.Handler
}

type listenerSnapshot struct {
	listener models.PortListener
	services []models.ServiceConfig
}

type responseRecorder struct {
	http.ResponseWriter
	statusCode int
	bytesOut   uint64
}

type oauthLoginPayload struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Remember bool   `json:"remember"`
}

type deterministicReader struct {
	seed    []byte
	counter uint64
	buffer  []byte
}

func (r *responseRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}

func (r *responseRecorder) Write(data []byte) (int, error) {
	if r.statusCode == 0 {
		r.statusCode = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(data)
	r.bytesOut += uint64(n)
	return n, err
}

func (r *responseRecorder) Flush() {
	if flusher, ok := r.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (r *responseRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := r.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("response writer does not support hijacking")
	}
	return hijacker.Hijack()
}

func (r *responseRecorder) Push(target string, opts *http.PushOptions) error {
	pusher, ok := r.ResponseWriter.(http.Pusher)
	if !ok {
		return http.ErrNotSupported
	}
	return pusher.Push(target, opts)
}

func (r *deterministicReader) Read(p []byte) (int, error) {
	filled := 0
	for filled < len(p) {
		if len(r.buffer) == 0 {
			blockInput := append([]byte{}, r.seed...)
			counterBytes := []byte{
				byte(r.counter >> 56), byte(r.counter >> 48), byte(r.counter >> 40), byte(r.counter >> 32),
				byte(r.counter >> 24), byte(r.counter >> 16), byte(r.counter >> 8), byte(r.counter),
			}
			blockInput = append(blockInput, counterBytes...)
			sum := sha256.Sum256(blockInput)
			r.buffer = sum[:]
			r.counter++
		}
		copied := copy(p[filled:], r.buffer)
		filled += copied
		r.buffer = r.buffer[copied:]
	}
	return filled, nil
}

var instance *Server
var once sync.Once

const defaultSecureSecret = security.DefaultSecureSecret

// 全局共享的 HTTP Transport，启用连接复用
var sharedTransport = &http.Transport{
	Proxy: http.ProxyFromEnvironment,
	DialContext: (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext,
	ForceAttemptHTTP2:     false,             // 不强制 HTTP/2，让协议自动协商
	MaxIdleConns:          200,               // 最大空闲连接数
	MaxIdleConnsPerHost:   50,                // 每个主机最大空闲连接数
	MaxConnsPerHost:       100,               // 每个主机最大连接数
	IdleConnTimeout:       90 * time.Second,  // 空闲连接超时
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
	ResponseHeaderTimeout: 60 * time.Second,
	DisableCompression:    true,              // 禁用自动压缩处理，让客户端与后端直接协商
	DisableKeepAlives:     false,             // 保持连接复用
	TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true,             // 跳过后端 HTTPS 证书验证
	},
}

// GetServer 获取代理服务器单例
func GetServer() *Server {
	once.Do(func() {
		privateKey, publicKeyPEM := mustGenerateOAuthKeyPair(defaultSecureSecret)
		ctx, cancel := context.WithCancel(context.Background())
		instance = &Server{
			ctx:               ctx,
			cancel:            cancel,
			servers:           make(map[string]*http.Server),
			routes:            make(map[string][]serviceRoute),
			listeners:         make(map[string]models.PortListener),
			proxies:           make(map[string]*httputil.ReverseProxy),
			lastGood:          make(map[string]listenerSnapshot),
			oauthPrivateKey:   privateKey,
			oauthPublicKeyPEM: publicKeyPEM,
		}
	})
	return instance
}

// Start 启动所有配置的监听
func (s *Server) Start() error {
	cfg := config.GetManager().GetConfig()
	var startupErrors []string

	for _, listener := range cfg.Listeners {
		if listener.Enabled {
			if err := s.StartListener(listener); err != nil {
				startupErrors = append(startupErrors, fmt.Sprintf("端口 %d(%s): %v", listener.Port, listener.Protocol, err))
			}
		}
	}
	if len(startupErrors) > 0 {
		return fmt.Errorf("%s", strings.Join(startupErrors, "; "))
	}
	return nil
}

// Stop 停止所有服务器
func (s *Server) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.cancel()

	for _, server := range s.servers {
		server.Shutdown(context.Background())
	}

	s.servers = make(map[string]*http.Server)
	s.routes = make(map[string][]serviceRoute)
	s.listeners = make(map[string]models.PortListener)
	s.proxies = make(map[string]*httputil.ReverseProxy)
	s.lastGood = make(map[string]listenerSnapshot)
	return nil
}

// Restart 重启服务器
func (s *Server) Restart() error {
	if err := s.Stop(); err != nil {
		return err
	}
	return s.Start()
}

// StartListener 启动指定监听器
func (s *Server) StartListener(listener models.PortListener) error {
	cfg := config.GetManager()
	services := cfg.GetServicesByPort(listener.ID)
	return s.applyListenerConfig(listener, services)
}

// StopListener 停止指定监听器
func (s *Server) StopListener(listenerID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if server, exists := s.servers[listenerID]; exists {
		if err := server.Shutdown(context.Background()); err != nil {
			return err
		}
		delete(s.servers, listenerID)
	}
	if snapshot, exists := s.lastGood[listenerID]; exists {
		s.cleanupListenerProxiesLocked(snapshot.services)
		delete(s.lastGood, listenerID)
	}
	delete(s.routes, listenerID)
	delete(s.listeners, listenerID)
	return nil
}

func cloneServices(services []models.ServiceConfig) []models.ServiceConfig {
	if len(services) == 0 {
		return nil
	}
	cloned := make([]models.ServiceConfig, len(services))
	copy(cloned, services)
	return cloned
}

func (s *Server) cleanupListenerProxiesLocked(services []models.ServiceConfig) {
	for _, service := range services {
		delete(s.proxies, service.ID)
	}
}

func (s *Server) buildListenerRoutes(listener models.PortListener, services []models.ServiceConfig) ([]serviceRoute, map[string]*httputil.ReverseProxy, error) {
	routes := make([]serviceRoute, 0, len(services))
	proxies := make(map[string]*httputil.ReverseProxy)
	for _, service := range services {
		if !service.Enabled {
			continue
		}
		handler, err := s.createHandler(service, proxies)
		if err != nil {
			serviceName := strings.TrimSpace(service.Name)
			if serviceName == "" {
				serviceName = service.ID
			}
			return nil, nil, fmt.Errorf("服务规则 %q 配置错误: %w", serviceName, err)
		}
		routes = append(routes, serviceRoute{
			service: service,
			handler: s.wrapServiceHandler(listener, service, handler),
		})
	}
	return routes, proxies, nil
}

func (s *Server) buildHTTPServer(listener models.PortListener) *http.Server {
	addr := fmt.Sprintf(":%d", listener.Port)
	listenerID := listener.ID
	return &http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if utils.GetCertificateManager().ServeHTTPChallenge(w, r) {
				return
			}
			// 动态获取监听器配置（用于 OAuth）
			s.mu.RLock()
			currentListener, hasListener := s.listeners[listenerID]
			routes := s.routes[listenerID]
			s.mu.RUnlock()

			if !hasListener {
				http.NotFound(w, r)
				return
			}

			if s.handleOAuthRequest(currentListener, w, r) {
				return
			}
			host := normalizeHost(r.Host)
			if route := matchServiceRoute(routes, host); route != nil {
				route.handler.ServeHTTP(w, r)
				return
			}
			http.NotFound(w, r)
		}),
	}
}

func (s *Server) createNetListener(listener models.PortListener) (net.Listener, error) {
	addr := fmt.Sprintf(":%d", listener.Port)
	baseListener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	if listener.Protocol != "https" {
		return baseListener, nil
	}
	tlsConfig := &tls.Config{
		GetCertificate: utils.GetCertificateManager().GetTLSCertificateForListener(listener.ID),
	}
	return tls.NewListener(baseListener, tlsConfig), nil
}

func (s *Server) serveListener(server *http.Server, listener models.PortListener, netListener net.Listener) {
	go func() {
		if err := server.Serve(netListener); err != nil && err != http.ErrServerClosed {
			fmt.Printf("Server error on port %d: %v\n", listener.Port, err)
		}
	}()
}

func (s *Server) restoreSnapshotLocked(snapshot listenerSnapshot) error {
	routes, proxies, err := s.buildListenerRoutes(snapshot.listener, snapshot.services)
	if err != nil {
		return err
	}
	server := s.buildHTTPServer(snapshot.listener)
	netListener, err := s.createNetListener(snapshot.listener)
	if err != nil {
		return err
	}
	s.servers[snapshot.listener.ID] = server
	s.routes[snapshot.listener.ID] = routes
	s.listeners[snapshot.listener.ID] = snapshot.listener
	s.cleanupListenerProxiesLocked(snapshot.services)
	for id, proxy := range proxies {
		s.proxies[id] = proxy
	}
	s.serveListener(server, snapshot.listener, netListener)
	return nil
}

func (s *Server) applyListenerConfig(listener models.PortListener, services []models.ServiceConfig) error {
	routes, proxies, err := s.buildListenerRoutes(listener, services)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	previousSnapshot, hasPrevious := s.lastGood[listener.ID]

	// 如果监听器已经在运行，只更新路由表，不重启服务器
	if _, exists := s.servers[listener.ID]; exists {
		// 清理旧的代理
		if hasPrevious {
			s.cleanupListenerProxiesLocked(previousSnapshot.services)
		}
		// 更新路由表和代理（热更新，无需重启）
		s.routes[listener.ID] = routes
		s.listeners[listener.ID] = listener
		for id, proxy := range proxies {
			s.proxies[id] = proxy
		}
		s.lastGood[listener.ID] = listenerSnapshot{
			listener: listener,
			services: cloneServices(services),
		}
		return nil
	}

	// 监听器不存在，需要创建新的服务器
	server := s.buildHTTPServer(listener)
	netListener, err := s.createNetListener(listener)
	if err != nil {
		if hasPrevious {
			if rollbackErr := s.restoreSnapshotLocked(previousSnapshot); rollbackErr != nil {
				return fmt.Errorf("重载失败: %v；回滚到上一次正确配置也失败: %v", err, rollbackErr)
			}
			return fmt.Errorf("重载失败，已回滚到上一次正确配置: %w", err)
		}
		return err
	}

	s.servers[listener.ID] = server
	s.routes[listener.ID] = routes
	s.listeners[listener.ID] = listener
	for id, proxy := range proxies {
		s.proxies[id] = proxy
	}
	s.lastGood[listener.ID] = listenerSnapshot{
		listener: listener,
		services: cloneServices(services),
	}
	s.serveListener(server, listener, netListener)
	return nil
}

func (s *Server) ReloadListener(listenerID string) error {
	listener := config.GetManager().GetListener(listenerID)
	if listener == nil {
		return fmt.Errorf("listener not found")
	}
	return s.StartListener(*listener)
}

func (s *Server) IsListenerRunning(listenerID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, exists := s.servers[listenerID]
	return exists
}

// createHandler 根据服务配置创建处理器
func (s *Server) createHandler(service models.ServiceConfig, proxies map[string]*httputil.ReverseProxy) (http.Handler, error) {
	switch service.Type {
	case models.ServiceTypeReverseProxy:
		return s.createReverseProxyHandler(service, proxies)
	case models.ServiceTypeStatic:
		return s.createStaticHandler(service)
	case models.ServiceTypeRedirect:
		return s.createRedirectHandler(service)
	case models.ServiceTypeURLJump:
		return s.createURLJumpHandler(service)
	case models.ServiceTypeTextOutput:
		return s.createTextOutputHandler(service)
	default:
		return nil, fmt.Errorf("不支持的服务类型: %s", service.Type)
	}
}

// createReverseProxyHandler 创建反向代理处理器
func (s *Server) createReverseProxyHandler(service models.ServiceConfig, proxies map[string]*httputil.ReverseProxy) (http.Handler, error) {
	configData, err := json.Marshal(service.Config)
	if err != nil {
		return nil, err
	}

	var cfg models.ReverseProxyConfig
	if err := json.Unmarshal(configData, &cfg); err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.Upstream) == "" {
		return nil, fmt.Errorf("代理地址不能为空")
	}

	targetURL, err := normalizeReverseProxyUpstream(cfg.Upstream)
	if err != nil {
		return nil, err
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	// 配置 Director 设置请求头
	proxy.Director = func(req *http.Request) {
		// 保存原始请求信息用于设置转发头
		originalHost := req.Host
		originalRemoteAddr := req.RemoteAddr
		originalTLS := req.TLS

		req.URL.Scheme = targetURL.Scheme
		req.URL.Host = targetURL.Host

		// Host 头处理
		if cfg.PreserveHost {
			// 保留原始 Host 头
			req.Host = originalHost
		} else if cfg.HostHeader != "" {
			// 使用自定义 Host 头
			req.Host = cfg.HostHeader
		} else {
			req.Host = targetURL.Host
		}

		// 路径处理
		if cfg.StripPathPrefix != "" && strings.HasPrefix(req.URL.Path, cfg.StripPathPrefix) {
			req.URL.Path = strings.TrimPrefix(req.URL.Path, cfg.StripPathPrefix)
			if req.URL.Path == "" {
				req.URL.Path = "/"
			}
		}
		if cfg.AddPathPrefix != "" {
			req.URL.Path = cfg.AddPathPrefix + req.URL.Path
		}

		if _, ok := req.Header["User-Agent"]; !ok {
			req.Header.Set("User-Agent", "")
		}

		// 隐藏发送给上游的请求头
		for _, header := range cfg.HideHeaderUp {
			req.Header.Del(header)
		}

		// 添加/修改发送给上游的请求头
		for key, value := range cfg.HeaderUp {
			if value == "" {
				req.Header.Del(key)
			} else {
				// 支持变量替换
				value = strings.ReplaceAll(value, "{host}", originalHost)
				value = strings.ReplaceAll(value, "{remote}", originalRemoteAddr)
				value = strings.ReplaceAll(value, "{scheme}", req.URL.Scheme)
				req.Header.Set(key, value)
			}
		}

		// 设置真实IP转发头（除非配置了信任上游代理头）
		if !cfg.TrustProxyHeaders {
			setForwardedHeaders(req, originalRemoteAddr, originalHost, originalTLS != nil)
		}
	}
	// 使用全局共享的 Transport，启用连接复用
	proxy.Transport = sharedTransport
	proxy.ModifyResponse = func(resp *http.Response) error {
		// 隐藏发送给客户端的响应头
		for _, header := range cfg.HideHeaderDown {
			resp.Header.Del(header)
		}
		// 添加/修改发送给客户端的响应头
		for key, value := range cfg.HeaderDown {
			if value == "" {
				resp.Header.Del(key)
			} else {
				resp.Header.Set(key, value)
			}
		}
		return nil
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		fmt.Printf("反向代理错误: %v\n", err)
		// 记录代理错误日志
		clientIP := getClientIP(r.RemoteAddr)
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			clientIP = strings.TrimSpace(parts[0])
		}
		security.GetAuditLogger().LogProxyError(
			cfg.Upstream,
			clientIP,
			fmt.Sprintf("%s %s: %s", r.Method, r.URL.Path, err.Error()),
			nil,
		)
		http.Error(w, "代理服务不可用", http.StatusBadGateway)
	}

	proxies[service.ID] = proxy

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 检查是否是 WebSocket 升级请求
		if isWebSocketUpgrade(r) {
			handleWebSocketProxy(w, r, targetURL)
			return
		}
		proxy.ServeHTTP(w, r)
	}), nil
}

// isWebSocketUpgrade 检查请求是否是 WebSocket 升级请求
func isWebSocketUpgrade(r *http.Request) bool {
	return strings.ToLower(r.Header.Get("Upgrade")) == "websocket"
}

// getClientIP 从请求中获取客户端真实IP
// 优先从 X-Forwarded-For 或 X-Real-IP 获取（如果有上游代理）
// 否则从 RemoteAddr 获取
func getClientIP(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}

// setForwardedHeaders 设置代理转发头，向后端传递真实客户端信息
func setForwardedHeaders(req *http.Request, remoteAddr, originalHost string, isHTTPS bool) {
	clientIP := getClientIP(remoteAddr)

	// X-Real-IP: 直接客户端IP
	req.Header.Set("X-Real-IP", clientIP)

	// X-Forwarded-For: 追加到已有的转发链
	if prior := req.Header.Get("X-Forwarded-For"); prior != "" {
		req.Header.Set("X-Forwarded-For", prior+", "+clientIP)
	} else {
		req.Header.Set("X-Forwarded-For", clientIP)
	}

	// X-Forwarded-Host: 原始请求的 Host
	if req.Header.Get("X-Forwarded-Host") == "" {
		req.Header.Set("X-Forwarded-Host", originalHost)
	}

	// X-Forwarded-Proto: 原始请求的协议
	if req.Header.Get("X-Forwarded-Proto") == "" {
		if isHTTPS {
			req.Header.Set("X-Forwarded-Proto", "https")
		} else {
			req.Header.Set("X-Forwarded-Proto", "http")
		}
	}
}

// WebSocket upgrader 配置
var wsUpgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin: func(r *http.Request) bool {
		return true // 允许所有来源
	},
}

// handleWebSocketProxy 使用 gorilla/websocket 处理 WebSocket 代理
func handleWebSocketProxy(w http.ResponseWriter, r *http.Request, targetURL *url.URL) {
	// 构建后端 WebSocket URL
	backendScheme := "ws"
	if targetURL.Scheme == "https" {
		backendScheme = "wss"
	}
	backendURL := url.URL{
		Scheme:   backendScheme,
		Host:     targetURL.Host,
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
	}

	// 准备连接后端的请求头
	requestHeader := http.Header{}
	// 需要排除的头（hop-by-hop 头 + WebSocket 握手头）
	excludeHeaders := map[string]bool{
		"Connection":               true,
		"Keep-Alive":               true,
		"Proxy-Authenticate":       true,
		"Proxy-Authorization":      true,
		"Te":                       true,
		"Trailer":                  true,
		"Transfer-Encoding":        true,
		"Upgrade":                  true,
		"Sec-Websocket-Key":        true,
		"Sec-Websocket-Version":    true,
		"Sec-Websocket-Extensions": true,
		"Sec-Websocket-Protocol":   true,
	}
	for key, values := range r.Header {
		if excludeHeaders[key] {
			continue
		}
		// 忽略大小写检查
		keyLower := strings.ToLower(key)
		if strings.HasPrefix(keyLower, "sec-websocket") {
			continue
		}
		// 跳过 Origin 头，后面单独处理
		if keyLower == "origin" {
			continue
		}
		for _, v := range values {
			requestHeader.Add(key, v)
		}
	}
	// 设置 Host 头为后端地址（某些后端检查 Host）
	requestHeader.Set("Host", targetURL.Host)
	// Origin 处理策略：保留原始 Origin 或不设置
	// 某些后端（如 VS Code Server）会检查 Origin 是否在允许列表中
	// 如果完全移除 Origin，大多数后端会放行
	// 这里选择不转发 Origin，让后端认为是直接连接
	// 添加真实IP转发头
	clientIP := getClientIP(r.RemoteAddr)
	requestHeader.Set("X-Real-IP", clientIP)
	if prior := r.Header.Get("X-Forwarded-For"); prior != "" {
		requestHeader.Set("X-Forwarded-For", prior+", "+clientIP)
	} else {
		requestHeader.Set("X-Forwarded-For", clientIP)
	}
	requestHeader.Set("X-Forwarded-Host", r.Host)
	if r.TLS != nil {
		requestHeader.Set("X-Forwarded-Proto", "https")
	} else {
		requestHeader.Set("X-Forwarded-Proto", "http")
	}

	// 连接后端 WebSocket
	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // 跳过后端 HTTPS 证书验证
		},
	}
	// 如果原始请求有 subprotocol，传递给后端
	if protocols := r.Header.Values("Sec-Websocket-Protocol"); len(protocols) > 0 {
		dialer.Subprotocols = protocols
	}

	backendConn, resp, err := dialer.Dial(backendURL.String(), requestHeader)
	if err != nil {
		errMsg := fmt.Sprintf("WebSocket 后端连接失败: %s -> %s, 错误: %v", r.URL.String(), backendURL.String(), err)
		if resp != nil {
			errMsg += fmt.Sprintf(" (状态码: %d)", resp.StatusCode)
		}
		fmt.Println(errMsg)
		http.Error(w, errMsg, http.StatusBadGateway)
		return
	}
	defer backendConn.Close()

	// 准备 upgrader 的响应头
	responseHeader := http.Header{}
	if subprotocol := backendConn.Subprotocol(); subprotocol != "" {
		responseHeader.Set("Sec-WebSocket-Protocol", subprotocol)
	}

	// 升级客户端连接
	clientConn, err := wsUpgrader.Upgrade(w, r, responseHeader)
	if err != nil {
		fmt.Printf("WebSocket 客户端升级失败: %v\n", err)
		return
	}
	defer clientConn.Close()

	// 双向转发 WebSocket 消息
	errChan := make(chan error, 2)

	// 客户端 -> 后端
	go func() {
		for {
			messageType, message, err := clientConn.ReadMessage()
			if err != nil {
				errChan <- err
				return
			}
			if err := backendConn.WriteMessage(messageType, message); err != nil {
				errChan <- err
				return
			}
		}
	}()

	// 后端 -> 客户端
	go func() {
		for {
			messageType, message, err := backendConn.ReadMessage()
			if err != nil {
				errChan <- err
				return
			}
			if err := clientConn.WriteMessage(messageType, message); err != nil {
				errChan <- err
				return
			}
		}
	}()

	// 等待任意一个方向出错
	<-errChan
}

func normalizeReverseProxyUpstream(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("代理地址不能为空")
	}
	targetURL, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	switch strings.ToLower(targetURL.Scheme) {
	case "ws":
		targetURL.Scheme = "http"
	case "wss":
		targetURL.Scheme = "https"
	}
	if targetURL.Scheme == "" || targetURL.Host == "" {
		return nil, fmt.Errorf("代理地址格式无效: %s", raw)
	}
	return targetURL, nil
}

// createStaticHandler 创建静态文件处理器
func (s *Server) createStaticHandler(service models.ServiceConfig) (http.Handler, error) {
	configData, err := json.Marshal(service.Config)
	if err != nil {
		return nil, err
	}

	var cfg models.StaticConfig
	if err := json.Unmarshal(configData, &cfg); err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.Root) == "" {
		return nil, fmt.Errorf("静态目录不能为空")
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		relativePath := strings.TrimPrefix(r.URL.Path, "/")
		fullPath := filepath.Join(cfg.Root, filepath.FromSlash(relativePath))
		info, err := os.Stat(fullPath)
		if err != nil {
			http.NotFound(w, r)
			return
		}

		if info.IsDir() {
			if cfg.Browse {
				if !strings.HasSuffix(r.URL.Path, "/") {
					http.Redirect(w, r, r.URL.Path+"/", http.StatusMovedPermanently)
					return
				}
				renderDirectoryBrowser(w, r, fullPath)
				return
			}
			indexName := strings.TrimSpace(cfg.Index)
			if indexName != "" {
				indexPath := filepath.Join(fullPath, filepath.FromSlash(indexName))
				indexInfo, indexErr := os.Stat(indexPath)
				if indexErr == nil && !indexInfo.IsDir() {
					serveStaticFile(w, r, indexPath)
					return
				}
			}
			http.NotFound(w, r)
			return
		}

		serveStaticFile(w, r, fullPath)
	}), nil
}

type directoryEntryView struct {
	Name    string
	Href    string
	Size    string
	ModTime string
	IsDir   bool
}

func renderDirectoryBrowser(w http.ResponseWriter, r *http.Request, fullPath string) {
	entries, err := os.ReadDir(fullPath)
	if err != nil {
		http.Error(w, "读取目录失败", http.StatusInternalServerError)
		return
	}

	items := make([]directoryEntryView, 0, len(entries))
	basePath := r.URL.Path
	if !strings.HasSuffix(basePath, "/") {
		basePath += "/"
	}

	sort.SliceStable(entries, func(i, j int) bool {
		leftDir := entries[i].IsDir()
		rightDir := entries[j].IsDir()
		if leftDir != rightDir {
			return leftDir
		}
		return strings.ToLower(entries[i].Name()) < strings.ToLower(entries[j].Name())
	})

	for _, entry := range entries {
		info, infoErr := entry.Info()
		if infoErr != nil {
			continue
		}
		name := entry.Name()
		href := basePath + url.PathEscape(name)
		if entry.IsDir() {
			href += "/"
		}
		items = append(items, directoryEntryView{
			Name:    name,
			Href:    href,
			Size:    formatDirectoryEntrySize(info),
			ModTime: info.ModTime().Format("2006-01-02 15:04:05"),
			IsDir:   entry.IsDir(),
		})
	}

	parentHref := ""
	cleanPath := path.Clean("/" + strings.TrimPrefix(r.URL.Path, "/"))
	if cleanPath != "/" {
		parentHref = path.Dir(cleanPath)
		if parentHref == "." {
			parentHref = "/"
		}
		if !strings.HasSuffix(parentHref, "/") {
			parentHref += "/"
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>文件浏览器 - %s</title>
<style>
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f8fafc;color:#0f172a}
.page{max-width:1100px;margin:0 auto;padding:28px 18px 40px}
.header{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;margin-bottom:20px;flex-wrap:wrap}
.title{font-size:28px;font-weight:800;line-height:1.2}
.path{margin-top:6px;color:#475569;font-size:14px;word-break:break-all}
.tip{color:#64748b;font-size:13px}
.card{background:#fff;border:1px solid #e2e8f0;border-radius:18px;box-shadow:0 10px 30px rgba(15,23,42,.06);overflow:hidden}
.toolbar{display:flex;justify-content:space-between;align-items:center;padding:16px 18px;border-bottom:1px solid #e2e8f0;background:#f8fafc;gap:12px;flex-wrap:wrap}
.back{display:inline-flex;align-items:center;gap:8px;color:#2563eb;text-decoration:none;font-weight:700}
.table{width:100%%;border-collapse:collapse}
.table th,.table td{padding:14px 18px;text-align:left;border-bottom:1px solid #eef2f7;font-size:14px}
.table th{background:#fff;color:#475569;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.name-link{display:inline-flex;align-items:center;gap:10px;color:#0f172a;text-decoration:none;font-weight:600}
.name-link:hover{color:#2563eb}
.icon{width:24px;text-align:center}
.type-dir{color:#2563eb}
.type-file{color:#64748b}
.muted{color:#64748b}
.empty{padding:34px 18px;text-align:center;color:#64748b}
@media (max-width: 720px){
.page{padding:18px 12px 28px}
.title{font-size:22px}
.table th,.table td{padding:12px 10px;font-size:13px}
.table th:nth-child(3),.table td:nth-child(3){display:none}
}
</style>
</head>
<body>
<div class="page">
  <div class="header">
    <div>
      <div class="title">文件浏览器</div>
      <div class="path">%s</div>
    </div>
  </div>
  <div class="card">
    <div class="toolbar">
      <div>共 %d 项</div>
      %s
    </div>
    %s
  </div>
</div>
</body>
</html>`,
		htmlEscape(strings.TrimPrefix(r.URL.Path, "/")),
		htmlEscape(r.URL.Path),
		len(items),
		directoryParentLink(parentHref),
		directoryTableHTML(items),
	)
}

func directoryParentLink(parentHref string) string {
	if parentHref == "" {
		return `<span class="muted">已在根目录</span>`
	}
	return `<a class="back" href="` + htmlEscape(parentHref) + `">← 返回上级目录</a>`
}

func directoryTableHTML(items []directoryEntryView) string {
	if len(items) == 0 {
		return `<div class="empty">当前目录为空</div>`
	}
	var builder strings.Builder
	builder.WriteString(`<table class="table"><thead><tr><th>名称</th><th>类型</th><th>大小</th><th>更新时间</th></tr></thead><tbody>`)
	for _, item := range items {
		icon := "📄"
		typeLabel := "文件"
		typeClass := "type-file"
		if item.IsDir {
			icon = "📁"
			typeLabel = "文件夹"
			typeClass = "type-dir"
		}
		builder.WriteString(`<tr>`)
		builder.WriteString(`<td><a class="name-link" href="` + htmlEscape(item.Href) + `"><span class="icon">` + icon + `</span><span>` + htmlEscape(item.Name) + `</span></a></td>`)
		builder.WriteString(`<td class="` + typeClass + `">` + typeLabel + `</td>`)
		builder.WriteString(`<td class="muted">` + htmlEscape(item.Size) + `</td>`)
		builder.WriteString(`<td class="muted">` + htmlEscape(item.ModTime) + `</td>`)
		builder.WriteString(`</tr>`)
	}
	builder.WriteString(`</tbody></table>`)
	return builder.String()
}

func formatDirectoryEntrySize(info os.FileInfo) string {
	if info.IsDir() {
		return "-"
	}
	size := info.Size()
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(size)/float64(div), "KMGTPE"[exp])
}

func serveStaticFile(w http.ResponseWriter, r *http.Request, filePath string) {
	file, err := os.Open(filePath)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil || info.IsDir() {
		http.NotFound(w, r)
		return
	}

	http.ServeContent(w, r, info.Name(), info.ModTime(), file)
}

// createRedirectHandler 创建重定向处理器
func (s *Server) createRedirectHandler(service models.ServiceConfig) (http.Handler, error) {
	configData, err := json.Marshal(service.Config)
	if err != nil {
		return nil, err
	}

	var cfg models.RedirectConfig
	if err := json.Unmarshal(configData, &cfg); err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.To) == "" {
		return nil, fmt.Errorf("重定向地址不能为空")
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 默认使用302临时重定向
		code := http.StatusFound
		http.Redirect(w, r, cfg.To, code)
	}), nil
}

// createURLJumpHandler 创建URL跳转处理器
func (s *Server) createURLJumpHandler(service models.ServiceConfig) (http.Handler, error) {
	configData, err := json.Marshal(service.Config)
	if err != nil {
		return nil, err
	}

	var cfg models.URLJumpConfig
	if err := json.Unmarshal(configData, &cfg); err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.TargetURL) == "" {
		return nil, fmt.Errorf("跳转地址不能为空")
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := cfg.TargetURL
		if cfg.PreservePath {
			u, _ := url.Parse(target)
			u.Path = r.URL.Path
			target = u.String()
		}
		http.Redirect(w, r, target, http.StatusFound)
	}), nil
}

// createTextOutputHandler 创建文本输出处理器
func (s *Server) createTextOutputHandler(service models.ServiceConfig) (http.Handler, error) {
	configData, err := json.Marshal(service.Config)
	if err != nil {
		return nil, err
	}

	var cfg models.TextOutputConfig
	if err := json.Unmarshal(configData, &cfg); err != nil {
		return nil, err
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentType := cfg.ContentType
		if contentType == "" {
			contentType = "text/plain; charset=utf-8"
		}
		w.Header().Set("Content-Type", contentType)

		statusCode := cfg.StatusCode
		if statusCode == 0 {
			statusCode = http.StatusOK
		}
		w.WriteHeader(statusCode)
		w.Write([]byte(cfg.Body))
	}), nil
}

func (s *Server) wrapServiceHandler(listener models.PortListener, service models.ServiceConfig, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username := getAuthenticatedUsername(r)
		if serviceOAuthEnabled(service) && username == "" {
			target := r.URL.RequestURI()
			if target == "" {
				target = "/"
			}
			http.Redirect(w, r, "/OAuth?redirect="+url.QueryEscape(target), http.StatusFound)
			return
		}

		start := time.Now()
		utils.GetMonitor().BeginRequest(listener, service)
		recorder := &responseRecorder{ResponseWriter: w}
		next.ServeHTTP(recorder, r)
		if recorder.statusCode == 0 {
			recorder.statusCode = http.StatusOK
		}
		utils.GetMonitor().RecordRequest(listener, service, r, recorder.statusCode, recorder.bytesOut, time.Since(start), username, serviceAccessLogEnabled(service))
	})
}

func (s *Server) handleOAuthRequest(listener models.PortListener, w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/OAuth" && r.URL.Path != "/_oauth/login" {
		return false
	}

	switch r.URL.Path {
	case "/_oauth/login":
		target := "/OAuth"
		if redirect := r.URL.RawQuery; redirect != "" {
			target += "?" + redirect
		}
		http.Redirect(w, r, target, http.StatusMovedPermanently)
		return true
	case "/OAuth":
		if r.Method == http.MethodGet {
			if getAuthenticatedUsername(r) != "" {
				return false
			}
			s.renderOAuthLoginPage(w, r, "")
			return true
		}
		if r.Method == http.MethodPost {
			s.handleOAuthLogin(w, r)
			return true
		}
	}

	http.NotFound(w, r)
	return true
}

func (s *Server) renderOAuthLoginPage(w http.ResponseWriter, r *http.Request, errMsg string) {
	redirectTarget := r.URL.Query().Get("redirect")
	oauth.RenderLoginPage(w, redirectTarget, errMsg, s.oauthPublicKeyPEM)
}

func (s *Server) handleOAuthLogin(w http.ResponseWriter, r *http.Request) {
	remoteAddr := r.RemoteAddr
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		remoteAddr = strings.Split(xff, ",")[0]
	}

	if err := r.ParseForm(); err != nil {
		fmt.Printf("OAuth 登录失败[表单解析失败] remote=%s err=%v\n", remoteAddr, err)
		security.GetAuditLogger().LogOAuthLogin("", remoteAddr, false, "表单解析失败")
		s.renderOAuthLoginPage(w, r, "表单解析失败")
		return
	}

	payload, err := s.parseOAuthLoginPayload(r)
	if err != nil {
		fmt.Printf("OAuth 登录失败[解密失败] remote=%s err=%v\n", remoteAddr, err)
		security.GetAuditLogger().LogOAuthLogin("", remoteAddr, false, err.Error())
		s.renderOAuthLoginPage(w, r, err.Error())
		return
	}

	username := strings.TrimSpace(payload.Username)
	password := payload.Password
	redirectTarget := r.FormValue("redirect")
	if redirectTarget == "" {
		redirectTarget = "/"
	}
	usedEncryptedPayload := strings.TrimSpace(r.FormValue("payload")) != ""

	user := config.GetManager().GetUserByUsername(username)
	if user == nil {
		fmt.Printf("OAuth 登录失败[用户不存在] remote=%s username=%s redirect=%s\n", remoteAddr, username, redirectTarget)
		security.GetAuditLogger().LogOAuthLogin(username, remoteAddr, false, "用户不存在")
		s.renderOAuthLoginPage(w, r, "用户名或密码错误")
		return
	}
	if !user.Enabled {
		fmt.Printf("OAuth 登录失败[用户被禁用] remote=%s username=%s redirect=%s\n", remoteAddr, username, redirectTarget)
		security.GetAuditLogger().LogOAuthLogin(username, remoteAddr, false, "用户已被禁用")
		s.renderOAuthLoginPage(w, r, "用户已被禁用")
		return
	}
	if !security.ComparePassword(user.Password, password) {
		fmt.Printf(
			"OAuth 登录失败[密码错误] remote=%s username=%s redirect=%s password_len=%d encrypted_payload=%t stored_secure_hash=%t default_admin_match=%t\n",
			remoteAddr,
			username,
			redirectTarget,
			len(password),
			usedEncryptedPayload,
			security.IsSecurePasswordHash(user.Password),
			username == "admin" && security.ComparePassword(user.Password, "admin"),
		)
		security.GetAuditLogger().LogOAuthLogin(username, remoteAddr, false, "密码错误")
		s.renderOAuthLoginPage(w, r, "用户名或密码错误")
		return
	}

	tokenTTL := 24 * time.Hour
	if payload.Remember {
		tokenTTL = 30 * 24 * time.Hour
	}
	token, err := utils.GenerateToken(user.Username, user.Role, tokenTTL)
	if err != nil {
		fmt.Printf("OAuth 登录失败[令牌生成失败] remote=%s username=%s err=%v\n", remoteAddr, username, err)
		security.GetAuditLogger().LogOAuthLogin(username, remoteAddr, false, "生成令牌失败")
		s.renderOAuthLoginPage(w, r, "生成登录令牌失败")
		return
	}

	security.GetAuditLogger().LogOAuthLogin(username, remoteAddr, true, "代理服务OAuth登录成功")
	utils.SetAuthCookie(w, token, r.TLS != nil, tokenTTL)
	http.Redirect(w, r, redirectTarget, http.StatusFound)
}

// ReloadService 重新加载服务
func (s *Server) ReloadService(service models.ServiceConfig) error {
	return s.ReloadListener(service.PortID)
}

// ExportConfig 导出配置为JSON
func (s *Server) ExportConfig() (map[string]interface{}, error) {
	cfg := config.GetManager().GetConfig()

	result := map[string]interface{}{
		"listeners": cfg.Listeners,
		"services":  cfg.Services,
	}

	return result, nil
}

func normalizeHost(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return strings.ToLower(h)
	}
	return strings.ToLower(host)
}

func matchServiceRoute(routes []serviceRoute, host string) *serviceRoute {
	var wildcardMatch *serviceRoute
	var defaultMatch *serviceRoute

	for i := range routes {
		domain := strings.TrimSpace(strings.ToLower(routes[i].service.Domain))
		if domain == "" || domain == "*" {
			if defaultMatch == nil {
				defaultMatch = &routes[i]
			}
			continue
		}

		if domain == host {
			return &routes[i]
		}

		if matchDomainPattern(domain, host) && wildcardMatch == nil {
			wildcardMatch = &routes[i]
		}
	}

	if wildcardMatch != nil {
		return wildcardMatch
	}
	return defaultMatch
}

func matchDomainPattern(pattern, host string) bool {
	if pattern == host {
		return true
	}

	if !strings.Contains(pattern, "*") {
		return false
	}

	quoted := regexp.QuoteMeta(pattern)
	regexPattern := "^" + strings.ReplaceAll(quoted, "\\*", ".*") + "$"
	matched, err := regexp.MatchString(regexPattern, host)
	if err != nil {
		return false
	}
	return matched
}

func serviceOAuthEnabled(service models.ServiceConfig) bool {
	return getServiceBoolOption(service.Config, "oauth", false) || service.RequireAuth
}

func serviceAccessLogEnabled(service models.ServiceConfig) bool {
	return getServiceBoolOption(service.Config, "access_log", true)
}

func getServiceBoolOption(configValue interface{}, key string, defaultValue bool) bool {
	data, err := json.Marshal(configValue)
	if err != nil {
		return defaultValue
	}

	var values map[string]interface{}
	if err := json.Unmarshal(data, &values); err != nil {
		return defaultValue
	}

	value, ok := values[key]
	if !ok {
		return defaultValue
	}

	typed, ok := value.(bool)
	if !ok {
		return defaultValue
	}
	return typed
}

func getAuthenticatedUsername(r *http.Request) string {
	claims, err := utils.GetAuthClaimsFromRequest(r)
	if err != nil || claims == nil {
		return ""
	}
	return claims.Username
}

func mustGenerateOAuthKeyPair(secret string) (*rsa.PrivateKey, string) {
	secret = security.NormalizeSecureSecret(secret)
	seed := sha256.Sum256([]byte(secret))
	privateKey, err := rsa.GenerateKey(&deterministicReader{seed: seed[:]}, 2048)
	if err != nil {
		panic(fmt.Sprintf("generate oauth rsa key failed: %v", err))
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		panic(fmt.Sprintf("marshal oauth public key failed: %v", err))
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicDER,
	})
	return privateKey, string(publicPEM)
}

func (s *Server) SetSecureSecret(secret string) {
	secret = security.NormalizeSecureSecret(secret)
	privateKey, publicKeyPEM := mustGenerateOAuthKeyPair(secret)
	s.mu.Lock()
	s.oauthPrivateKey = privateKey
	s.oauthPublicKeyPEM = publicKeyPEM
	s.mu.Unlock()
}

func (s *Server) GetOAuthPublicKeyPEM() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.oauthPublicKeyPEM
}

// GetOAuthPrivateKey 返回 OAuth 私钥
func (s *Server) GetOAuthPrivateKey() *rsa.PrivateKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.oauthPrivateKey
}

func (s *Server) DecryptSecurePayload(payload string) ([]byte, error) {
	s.mu.RLock()
	privateKey := s.oauthPrivateKey
	s.mu.RUnlock()
	if privateKey == nil {
		return nil, fmt.Errorf("未初始化安全密钥")
	}

	payload = strings.TrimSpace(payload)
	if payload == "" {
		return nil, fmt.Errorf("缺少加密数据")
	}

	cipherBytes, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		cipherBytes, err = base64.StdEncoding.DecodeString(payload)
		if err != nil {
			return nil, fmt.Errorf("登录数据解码失败")
		}
	}

	plainBytes, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, cipherBytes, nil)
	if err != nil {
		return nil, fmt.Errorf("登录数据解密失败")
	}
	return plainBytes, nil
}

func (s *Server) parseOAuthLoginPayload(r *http.Request) (*oauthLoginPayload, error) {
	encryptedPayload := strings.TrimSpace(r.FormValue("payload"))
	if encryptedPayload == "" {
		username := strings.TrimSpace(r.FormValue("username"))
		password := r.FormValue("password")
		if username == "" || password == "" {
			return nil, fmt.Errorf("请填写用户名和密码")
		}
		return &oauthLoginPayload{
			Username: username,
			Password: password,
			Remember: r.FormValue("remember") == "true" || r.FormValue("remember") == "on",
		}, nil
	}

	plainBytes, err := s.DecryptSecurePayload(encryptedPayload)
	if err != nil {
		return nil, err
	}

	var payload oauthLoginPayload
	if err := json.Unmarshal(plainBytes, &payload); err != nil {
		return nil, fmt.Errorf("登录数据解析失败")
	}
	if strings.TrimSpace(payload.Username) == "" || payload.Password == "" {
		return nil, fmt.Errorf("请填写用户名和密码")
	}
	return &payload, nil
}

func oauthErrorHTML(message string) string {
	if message == "" {
		return ""
	}
	return `<div class="error">` + htmlEscape(message) + `</div>`
}

func htmlEscape(value string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		`"`, "&quot;",
		"<", "&lt;",
		">", "&gt;",
		"'", "&#39;",
	)
	return replacer.Replace(value)
}
