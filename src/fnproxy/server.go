package fnproxy

import (
	"bufio"
	"bytes"
	"context"
	"io"
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
	"github.com/quic-go/quic-go/http3"
)

// Server 代理服务器管理
type Server struct {
	mu                sync.RWMutex
	ctx               context.Context
	cancel            context.CancelFunc
	servers           map[string]*http.Server
	h3servers         map[string]*http3.Server  // HTTP/3 服务器（QUIC）
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

// newUpstreamTLSConfig 反代访问上游 HTTPS、以及 WebSocket 拨号 WSS 时使用的 TLS 客户端配置。
// 始终跳过对上游证书的校验（自签、过期、CN/SAN 不匹配等），便于内网或测试环境对接。
func newUpstreamTLSConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		// 启用 TLS 会话缓存，加速 TLS 重连
		ClientSessionCache: tls.NewLRUClientSessionCache(256),
	}
}

// 全局共享的 HTTP Transport，启用连接复用和性能优化
var sharedTransport = &http.Transport{
	Proxy: http.ProxyFromEnvironment,
	DialContext: (&net.Dialer{
		Timeout:   10 * time.Second,  // 连接超时缩短
		KeepAlive: 30 * time.Second,
		DualStack: true,              // 启用 IPv4/IPv6 双栈
	}).DialContext,
	ForceAttemptHTTP2:     true,              // 尝试使用 HTTP/2，多路复用提升并发性能
	MaxIdleConns:          500,               // 增加最大空闲连接数
	MaxIdleConnsPerHost:   100,               // 增加每个主机最大空闲连接数
	MaxConnsPerHost:       200,               // 增加每个主机最大连接数
	IdleConnTimeout:       120 * time.Second, // 空闲连接超时延长
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
	ResponseHeaderTimeout: 60 * time.Second,
	DisableCompression:    true,              // 禁用自动压缩处理，让客户端与后端直接协商
	DisableKeepAlives:     false,             // 保持连接复用
	WriteBufferSize:       64 * 1024,         // 增加写缓冲区
	ReadBufferSize:        64 * 1024,         // 增加读缓冲区
	TLSClientConfig:       newUpstreamTLSConfig(),
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
			h3servers:         make(map[string]*http3.Server),
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
	for _, h3server := range s.h3servers {
		h3server.Close()
	}

	s.servers = make(map[string]*http.Server)
	s.h3servers = make(map[string]*http3.Server)
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
	// 停止 HTTP/3 服务器
	if h3server, exists := s.h3servers[listenerID]; exists {
		h3server.Close()
		delete(s.h3servers, listenerID)
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

// computeHTTPVersionSupport 从服务列表聊合 HTTP 版本支持：任一服务启用则监听器就启用
func computeHTTPVersionSupport(services []models.ServiceConfig) (http2, http3 bool) {
	for _, svc := range services {
		if !svc.Enabled {
			continue
		}
		if svc.HTTP2 {
			http2 = true
		}
		if svc.HTTP3 {
			http3 = true
		}
	}
	return
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

// buildListenerHandler 构建监听器请求处理器（HTTP/1.1+HTTP/2 和 HTTP/3 共用同一套业务逻辑）
func (s *Server) buildListenerHandler(listenerID string) http.Handler {
	// 核心业务处理器（经过防火墙检查后执行）
	coreHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 动态获取监听器配置（用于 OAuth 和 Alt-Svc 头广播）
		s.mu.RLock()
		currentListener, hasListener := s.listeners[listenerID]
		routes := s.routes[listenerID]
		_, h3Active := s.h3servers[listenerID]
		s.mu.RUnlock()

		if !hasListener {
			http.NotFound(w, r)
			return
		}

		// 如果 HTTP/3 服务器正在运行，通过 Alt-Svc 头通知客户端可升级到 QUIC
		if h3Active {
			w.Header().Set("Alt-Svc", fmt.Sprintf(`h3=":%d"; ma=86400`, currentListener.Port))
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
	})

	// 防火墙包裹核心处理器（优先级最高）
	firewallHandler := utils.FirewallMiddleware(coreHandler)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// ACME HTTP-01 证书验证请求必须绕过防火墙（公网可访问性要求）
		if utils.GetCertificateManager().ServeHTTPChallenge(w, r) {
			return
		}
		firewallHandler.ServeHTTP(w, r)
	})
}

func (s *Server) buildHTTPServer(listener models.PortListener) *http.Server {
	return &http.Server{
		Addr:              fmt.Sprintf(":%d", listener.Port),
		Handler:           s.buildListenerHandler(listener.ID),
		ReadHeaderTimeout: 10 * time.Second,  // 读取请求头超时
		IdleTimeout:       120 * time.Second, // 空闲连接超时，支持 Keep-Alive
		MaxHeaderBytes:    1 << 20,           // 最大请求头大小 1MB
	}
}

func (s *Server) createNetListener(listener models.PortListener, http2 bool) (net.Listener, error) {
	addr := fmt.Sprintf(":%d", listener.Port)
	baseListener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	if listener.Protocol != "https" {
		return baseListener, nil
	}
	// 根据 HTTP2 开关决定 ALPN 协议列表
	nextProtos := []string{"http/1.1"}
	if http2 {
		nextProtos = []string{"h2", "http/1.1"}
	}
	tlsConfig := &tls.Config{
		GetCertificate: utils.GetCertificateManager().GetTLSCertificateForListener(listener.ID),
		NextProtos:     nextProtos,
	}
	// 使用协议嗅探监听器，支持 HTTP 自动跳转到 HTTPS
	return newProtocolSniffListener(baseListener, tlsConfig), nil
}

// protocolSniffListener 是一个协议嗅探监听器，能够检测客户端发送的是 HTTP 还是 TLS
// 如果是 HTTP 请求，返回 301 重定向到 HTTPS
type protocolSniffListener struct {
	net.Listener
	tlsConfig *tls.Config
}

// protocolSniffConn 包装连接，用于协议检测
type protocolSniffConn struct {
	net.Conn
	bufReader *bufio.Reader
	isTLS     bool
}

func (c *protocolSniffConn) Read(p []byte) (n int, err error) {
	return c.bufReader.Read(p)
}

// newProtocolSniffListener 创建协议嗅探监听器
func newProtocolSniffListener(base net.Listener, tlsConfig *tls.Config) net.Listener {
	return &protocolSniffListener{
		Listener:  base,
		tlsConfig: tlsConfig,
	}
}

// Accept 接受连接并检测协议类型
func (l *protocolSniffListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}

		// 设置读取超时，防止客户端不发送数据导致连接卡住
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))

		// 使用带缓冲的 reader 来偷看前几个字节
		bufReader := bufio.NewReader(conn)

		// 偷看前 5 个字节来判断协议类型
		peek, err := bufReader.Peek(5)
		if err != nil {
			// 如果无法读取，可能是连接已关闭或超时，继续接受下一个连接
			conn.Close()
			continue
		}

		// 清除读取超时
		conn.SetReadDeadline(time.Time{})

		// TLS ClientHello 的第一个字节是 0x16 (ContentType: Handshake)
		// HTTP 请求通常以 "GET ", "POST ", "HEAD ", "PUT ", "DELETE", "OPTIONS", "PATCH " 等开头
		isTLS := len(peek) > 0 && peek[0] == 0x16

		if !isTLS {
			// 这是一个 HTTP 请求，同步处理重定向后关闭连接，继续接受下一个连接
			l.handleHTTPRedirect(conn, bufReader)
			conn.Close()
			continue
		}

		// 这是一个 TLS 连接，包装后返回
		tlsConn := tls.Server(&protocolSniffConn{Conn: conn, bufReader: bufReader, isTLS: true}, l.tlsConfig)
		return tlsConn, nil
	}
}

// handleHTTPRedirect 处理 HTTP 重定向
func (l *protocolSniffListener) handleHTTPRedirect(conn net.Conn, bufReader *bufio.Reader) {
	// 设置读取超时
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	// 读取 HTTP 请求的第一行来获取 Host
	line, err := bufReader.ReadString('\n')
	if err != nil {
		return
	}

	// 解析请求行，例如: "GET /path HTTP/1.1"
	parts := strings.Split(strings.TrimSpace(line), " ")
	if len(parts) < 2 {
		return
	}

	path := parts[1]

	// 继续读取请求头，查找 Host 头
	host := ""
	for {
		line, err := bufReader.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)
		if line == "" {
			break // 请求头结束
		}
		if strings.HasPrefix(strings.ToLower(line), "host:") {
			host = strings.TrimSpace(line[5:])
			break
		}
	}

	// 构建重定向 URL
	var redirectURL string
	if host != "" {
		redirectURL = fmt.Sprintf("https://%s%s", host, path)
	} else {
		// 如果没有 Host 头，使用连接的本地地址
		redirectURL = fmt.Sprintf("https://%s%s", conn.LocalAddr().String(), path)
	}

	// 发送 301 重定向响应
	response := fmt.Sprintf("HTTP/1.1 301 Moved Permanently\r\n"+
		"Location: %s\r\n"+
		"Content-Type: text/html; charset=utf-8\r\n"+
		"Content-Length: 0\r\n"+
		"Connection: close\r\n\r\n", redirectURL)

	conn.Write([]byte(response))
}

func (s *Server) serveListener(server *http.Server, listener models.PortListener, netListener net.Listener) {
	go func() {
		if err := server.Serve(netListener); err != nil && err != http.ErrServerClosed {
			fmt.Printf("Server error on port %d: %v\n", listener.Port, err)
		}
	}()
}

// startH3ServerLocked 启动 HTTP/3（QUIC）服务器，与 HTTP/1.1+HTTP/2 的 TCP 服务器并行运行于同一 UDP 端口
// 调用前需持有写锁（mu.Lock）
func (s *Server) startH3ServerLocked(listener models.PortListener) {
	listenerID := listener.ID
	tlsConfig := http3.ConfigureTLSConfig(&tls.Config{
		GetCertificate: utils.GetCertificateManager().GetTLSCertificateForListener(listenerID),
	})
	h3server := &http3.Server{
		Handler:   s.buildListenerHandler(listenerID),
		TLSConfig: tlsConfig,
		Addr:      fmt.Sprintf(":%d", listener.Port),
	}
	s.h3servers[listenerID] = h3server
	go func() {
		if err := h3server.ListenAndServe(); err != nil {
			fmt.Printf("HTTP/3 服务器错误 端口 %d: %v\n", listener.Port, err)
		}
	}()
}

func (s *Server) restoreSnapshotLocked(snapshot listenerSnapshot) error {
	routes, proxies, err := s.buildListenerRoutes(snapshot.listener, snapshot.services)
	if err != nil {
		return err
	}
	http2, http3 := computeHTTPVersionSupport(snapshot.services)
	server := s.buildHTTPServer(snapshot.listener)
	netListener, err := s.createNetListener(snapshot.listener, http2)
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
	// 恢复 HTTP/3 服务器（如果服务配置启用）
	if http3 && snapshot.listener.Protocol == "https" {
		s.startH3ServerLocked(snapshot.listener)
	}
	s.serveListener(server, snapshot.listener, netListener)
	return nil
}

func (s *Server) applyListenerConfig(listener models.PortListener, services []models.ServiceConfig) error {
	routes, proxies, err := s.buildListenerRoutes(listener, services)
	if err != nil {
		return err
	}

	// 从所有服务聊合有效的 HTTP 版本支持
	effectiveHTTP2, effectiveHTTP3 := computeHTTPVersionSupport(services)

	s.mu.Lock()
	defer s.mu.Unlock()

	previousSnapshot, hasPrevious := s.lastGood[listener.ID]

	// 如果监听器已经在运行
	if _, exists := s.servers[listener.ID]; exists {
		// 计算之前的有效 HTTP2
		var prevHTTP2 bool
		if hasPrevious {
			prevHTTP2, _ = computeHTTPVersionSupport(previousSnapshot.services)
		}

		// HTTP2 发生变化时需要重建 TLS 监听器（ALPN NextProtos 已固定在握手层）
		needTCPRestart := listener.Protocol == "https" && prevHTTP2 != effectiveHTTP2
		if needTCPRestart {
			s.servers[listener.ID].Shutdown(context.Background())
			delete(s.servers, listener.ID)
			if oldH3, hasOldH3 := s.h3servers[listener.ID]; hasOldH3 {
				oldH3.Close()
				delete(s.h3servers, listener.ID)
			}
		}

		// 更新路由和代理
		if hasPrevious {
			s.cleanupListenerProxiesLocked(previousSnapshot.services)
		}
		s.routes[listener.ID] = routes
		s.listeners[listener.ID] = listener
		for id, proxy := range proxies {
			s.proxies[id] = proxy
		}
		s.lastGood[listener.ID] = listenerSnapshot{
			listener: listener,
			services: cloneServices(services),
		}

		if needTCPRestart {
			// 重建 TCP 监听器
			server := s.buildHTTPServer(listener)
			netListener, err := s.createNetListener(listener, effectiveHTTP2)
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
			if effectiveHTTP3 && listener.Protocol == "https" {
				s.startH3ServerLocked(listener)
			}
			s.serveListener(server, listener, netListener)
			return nil
		}

		// 热更新 H3（无需重启 TCP）
		if oldH3, hasOldH3 := s.h3servers[listener.ID]; hasOldH3 {
			oldH3.Close()
			delete(s.h3servers, listener.ID)
		}
		if effectiveHTTP3 && listener.Protocol == "https" {
			s.startH3ServerLocked(listener)
		}
		return nil
	}

	// 监听器不存在，需要创建新的服务器
	server := s.buildHTTPServer(listener)
	netListener, err := s.createNetListener(listener, effectiveHTTP2)
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
	if effectiveHTTP3 && listener.Protocol == "https" {
		s.startH3ServerLocked(listener)
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
	configData = mergeExtendJSON(configData, service.ExtendJSON)

	// 检查 ExtendJSON 中是否显式设置了 preserve_host
	preserveHostExplicitlySet := false
	if service.ExtendJSON != "" {
		var extendMap map[string]interface{}
		if err := json.Unmarshal([]byte(service.ExtendJSON), &extendMap); err == nil {
			if _, ok := extendMap["preserve_host"]; ok {
				preserveHostExplicitlySet = true
			}
		}
	}

	if err := json.Unmarshal(configData, &cfg); err != nil {
		return nil, err
	}

	// 如果用户没有显式设置 preserve_host，默认为 true
	if !preserveHostExplicitlySet {
		cfg.PreserveHost = true
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
		originalHost := req.Host
		originalRemoteAddr := req.RemoteAddr
		origHeader := req.Header.Clone()

		req.URL.Scheme = targetURL.Scheme
		req.URL.Host = targetURL.Host

		if len(cfg.AllowHeaderUp) > 0 {
			applyAllowHeaderUp(req.Header, origHeader, cfg.AllowHeaderUp)
		}

		if cfg.PreserveHost {
			req.Host = originalHost
		} else if cfg.HostHeader != "" {
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

		// preserve_host=false：Host 已指向上游；Origin、Referer 同步为上游身份（在 header_up 之前，便于 header_up 覆盖）
		if !cfg.PreserveHost {
			rewriteOriginRefererToUpstream(req.Header, targetURL, cfg.HostHeader)
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

		// 真实 IP / 转发头（omit_proxy_headers 优先级最高：不附带、不保留任何代理转发信息）
		if cfg.OmitProxyHeaders {
			stripProxyIdentityHeaders(req.Header)
		} else if cfg.HideRealIP {
			stripProxyIdentityHeaders(req.Header)
		} else if !cfg.TrustProxyHeaders {
			realAddr := originalRemoteAddr
			if cfg.ClientIPHeader != "" {
				if headerVal := origHeader.Get(cfg.ClientIPHeader); headerVal != "" {
					parts := strings.Split(headerVal, ",")
					realAddr = strings.TrimSpace(parts[0])
				}
			}
			setForwardedHeaders(req, origHeader, realAddr, originalHost, utils.RequestIsHTTPS(req))
		}
		req.Header.Del("Host")
	}
	// Transport 配置：默认使用全局共享 Transport，如有超时覆盖则克隆一个
	if cfg.ResponseTimeout > 0 {
		customTransport := sharedTransport.Clone()
		customTransport.ResponseHeaderTimeout = time.Duration(cfg.ResponseTimeout) * time.Second
		proxy.Transport = customTransport
	} else {
		proxy.Transport = sharedTransport
	}
	// 流式响应刷新间隔
	if cfg.FlushInterval == -1 {
		proxy.FlushInterval = -1
	} else if cfg.FlushInterval > 0 {
		proxy.FlushInterval = time.Duration(cfg.FlushInterval) * time.Millisecond
	}
	proxy.ModifyResponse = func(resp *http.Response) error {
		// 设置缓存头（header_down 可覆盖）
		setCacheControlHeader(resp.Header, cfg.CacheMaxAge)
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
		// 总请求超时（含转发+响应完成的完整周期）
		if cfg.Timeout > 0 {
			ctx, cancel := context.WithTimeout(r.Context(), time.Duration(cfg.Timeout)*time.Second)
			defer cancel()
			r = r.WithContext(ctx)
		}
		// 缓冲请求体（完整读取后再转发，允许后续重试；同时修正 Content-Length）
		if cfg.BufferRequests && r.Body != nil && r.Body != http.NoBody {
			body, readErr := io.ReadAll(r.Body)
			r.Body.Close()
			if readErr != nil {
				http.Error(w, "读取请求体失败", http.StatusBadRequest)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			r.ContentLength = int64(len(body))
		}
		// 限制最大请求体大小
		if cfg.MaxBodySize > 0 {
			r.Body = http.MaxBytesReader(w, r.Body, cfg.MaxBodySize*1024*1024)
		}
		// 检查是否是 WebSocket 升级请求
		if isWebSocketUpgrade(r) {
			handleWebSocketProxy(w, r, targetURL, cfg)
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

// allowHeaderUpSet 构建规范化后的请求头白名单（忽略空串）。
func allowHeaderUpSet(allow []string) map[string]struct{} {
	m := make(map[string]struct{})
	for _, a := range allow {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		m[http.CanonicalHeaderKey(a)] = struct{}{}
	}
	return m
}

// applyAllowHeaderUp 将 dst 替换为「仅含 orig 中、且名称在白名单内的头」；并移除 Host 键（由 req.Host 决定发往上游的 Host）。
func applyAllowHeaderUp(dst, orig http.Header, allow []string) {
	allowed := allowHeaderUpSet(allow)
	if len(allowed) == 0 {
		for k := range dst {
			delete(dst, k)
		}
		dst.Del("Host")
		return
	}
	for k := range dst {
		delete(dst, k)
	}
	for name, vals := range orig {
		canon := http.CanonicalHeaderKey(name)
		if _, ok := allowed[canon]; !ok {
			continue
		}
		dst[canon] = append([]string(nil), vals...)
	}
	dst.Del("Host")
}

// wsDialNeverForwardHeader WebSocket 拨号时永不转发的头（握手由库重建或属于逐跳）。
func wsDialNeverForwardHeader(canon string) bool {
	switch canon {
	case "Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
		"Te", "Trailer", "Transfer-Encoding", "Upgrade":
		return true
	}
	if strings.HasPrefix(strings.ToLower(canon), "sec-websocket") {
		return true
	}
	return false
}

// copyWSHeadersWithOptionalAllow 构建发往上游 WebSocket 的 Header；allow 非空时仅复制白名单内且非 wsDialNeverForward 的字段。
func copyWSHeadersWithOptionalAllow(dst http.Header, src http.Header, allow []string) {
	if len(allow) == 0 {
		excludeHeaders := map[string]bool{
			"Connection": true, "Keep-Alive": true, "Proxy-Authenticate": true,
			"Proxy-Authorization": true, "Te": true, "Trailer": true,
			"Transfer-Encoding": true, "Upgrade": true,
			"Sec-Websocket-Key": true, "Sec-Websocket-Version": true,
			"Sec-Websocket-Extensions": true, "Sec-Websocket-Protocol": true,
		}
		for key, values := range src {
			if excludeHeaders[key] {
				continue
			}
			keyLower := strings.ToLower(key)
			if strings.HasPrefix(keyLower, "sec-websocket") {
				continue
			}
			if keyLower == "origin" {
				continue
			}
			for _, v := range values {
				dst.Add(key, v)
			}
		}
		return
	}
	allowed := allowHeaderUpSet(allow)
	for name, vals := range src {
		canon := http.CanonicalHeaderKey(name)
		if wsDialNeverForwardHeader(canon) {
			continue
		}
		if _, ok := allowed[canon]; !ok {
			continue
		}
		for _, v := range vals {
			dst.Add(canon, v)
		}
	}
}

// stripProxyIdentityHeaders 移除常见代理/转发相关请求头（不添加新头，仅删除）。
func stripProxyIdentityHeaders(h http.Header) {
	names := []string{
		"X-Real-IP",
		"X-Forwarded-For",
		"X-Forwarded-Host",
		"X-Forwarded-Proto",
		"X-Forwarded-Port",
		"Forwarded",
	}
	for _, name := range names {
		h.Del(name)
	}
}

// rewriteOriginRefererToUpstream 在 preserve_host=false 时，将 Origin、Referer 重写为与上游 Host（target 或 host_header）一致，
// 与发往上游的 Host 头语义对齐，避免后端仍看到客户端入口域名。
func rewriteOriginRefererToUpstream(h http.Header, targetURL *url.URL, hostHeader string) {
	host := targetURL.Host
	if hostHeader != "" {
		host = hostHeader
	}
	base := targetURL.Scheme + "://" + host
	h.Set("Origin", base)
	if ref := h.Get("Referer"); ref != "" {
		if u, err := url.Parse(ref); err == nil && u.Host != "" {
			u.Scheme = targetURL.Scheme
			u.Host = host
			h.Set("Referer", u.String())
		}
	}
}

// forwardedHeadersApply 将真实 IP / 转发链写入目标 Header（供 HTTP 代理与 WebSocket 拨号共用）
func forwardedHeadersApply(dst http.Header, priorXFF, remoteAddr, originalHost string, isHTTPS bool) {
	clientIP := getClientIP(remoteAddr)
	dst.Set("X-Real-IP", clientIP)
	if priorXFF != "" {
		dst.Set("X-Forwarded-For", priorXFF+", "+clientIP)
	} else {
		dst.Set("X-Forwarded-For", clientIP)
	}
	if dst.Get("X-Forwarded-Host") == "" {
		dst.Set("X-Forwarded-Host", originalHost)
	}
	if dst.Get("X-Forwarded-Proto") == "" {
		if isHTTPS {
			dst.Set("X-Forwarded-Proto", "https")
		} else {
			dst.Set("X-Forwarded-Proto", "http")
		}
	}
}

// setForwardedHeaders 设置代理转发头，向后端传递真实客户端信息（prior 取自原始请求 origHeader，避免 allow_header_up 去掉 XFF 后无法拼接链）。
func setForwardedHeaders(req *http.Request, origHeader http.Header, remoteAddr, originalHost string, isHTTPS bool) {
	prior := origHeader.Get("X-Forwarded-For")
	forwardedHeadersApply(req.Header, prior, remoteAddr, originalHost, isHTTPS)
}

// WebSocket upgrader 配置
var wsUpgrader = websocket.Upgrader{
	ReadBufferSize:  32 * 1024, // 增加读缓冲区
	WriteBufferSize: 32 * 1024, // 增加写缓冲区
	CheckOrigin: func(r *http.Request) bool {
		return true // 允许所有来源
	},
	EnableCompression: true, // 启用 WebSocket 压缩
}

// handleWebSocketProxy 使用 gorilla/websocket 处理 WebSocket 代理
func handleWebSocketProxy(w http.ResponseWriter, r *http.Request, targetURL *url.URL, cfg models.ReverseProxyConfig) {
	originalHost := r.Host
	originalRemoteAddr := r.RemoteAddr
	origHeader := r.Header.Clone()

	path := r.URL.Path
	if cfg.StripPathPrefix != "" && strings.HasPrefix(path, cfg.StripPathPrefix) {
		path = strings.TrimPrefix(path, cfg.StripPathPrefix)
		if path == "" {
			path = "/"
		}
	}
	if cfg.AddPathPrefix != "" {
		path = cfg.AddPathPrefix + path
	}

	// 构建后端 WebSocket URL（https 上游一律 wss；http 上游默认 ws，仅 wss 时设 websocket_upstream_tls）
	backendScheme := "ws"
	if targetURL.Scheme == "https" || (targetURL.Scheme == "http" && cfg.WebSocketUpstreamTLS) {
		backendScheme = "wss"
	}
	backendURL := url.URL{
		Scheme:   backendScheme,
		Host:     targetURL.Host,
		Path:     path,
		RawQuery: r.URL.RawQuery,
	}

	var upstreamHost string
	if cfg.PreserveHost {
		upstreamHost = originalHost
	} else if cfg.HostHeader != "" {
		upstreamHost = cfg.HostHeader
	} else {
		upstreamHost = targetURL.Host
	}

	requestHeader := http.Header{}
	copyWSHeadersWithOptionalAllow(requestHeader, r.Header, cfg.AllowHeaderUp)
	if _, ok := requestHeader["User-Agent"]; !ok {
		requestHeader.Set("User-Agent", "")
	}
	for _, header := range cfg.HideHeaderUp {
		requestHeader.Del(header)
	}
	// WebSocket 代理始终保留客户端的 Origin，避免后端（如 VS Code Server）的跨域校验失败
	if o := r.Header.Get("Origin"); o != "" {
		requestHeader.Set("Origin", o)
	}
	// Referer 仍根据 PreserveHost 策略处理
	if cfg.PreserveHost {
		if ref := r.Header.Get("Referer"); ref != "" {
			requestHeader.Set("Referer", ref)
		}
	} else {
		if ref := r.Header.Get("Referer"); ref != "" {
			if u, err := url.Parse(ref); err == nil && u.Host != "" {
				host := targetURL.Host
				if cfg.HostHeader != "" {
					host = cfg.HostHeader
				}
				u.Scheme = targetURL.Scheme
				u.Host = host
				requestHeader.Set("Referer", u.String())
			}
		}
	}
	for key, value := range cfg.HeaderUp {
		if value == "" {
			requestHeader.Del(key)
		} else {
			value = strings.ReplaceAll(value, "{host}", originalHost)
			value = strings.ReplaceAll(value, "{remote}", originalRemoteAddr)
			value = strings.ReplaceAll(value, "{scheme}", targetURL.Scheme)
			requestHeader.Set(key, value)
		}
	}

	requestHeader.Set("Host", upstreamHost)

	if cfg.OmitProxyHeaders {
		stripProxyIdentityHeaders(requestHeader)
	} else if cfg.HideRealIP {
		stripProxyIdentityHeaders(requestHeader)
	} else if !cfg.TrustProxyHeaders {
		realAddr := originalRemoteAddr
		if cfg.ClientIPHeader != "" {
			if headerVal := origHeader.Get(cfg.ClientIPHeader); headerVal != "" {
				parts := strings.Split(headerVal, ",")
				realAddr = strings.TrimSpace(parts[0])
			}
		}
		prior := origHeader.Get("X-Forwarded-For")
		forwardedHeadersApply(requestHeader, prior, realAddr, originalHost, utils.RequestIsHTTPS(r))
	}

	// 连接后端 WebSocket
	dialer := websocket.Dialer{
		HandshakeTimeout:  10 * time.Second,
		TLSClientConfig:   newUpstreamTLSConfig(),
		ReadBufferSize:    32 * 1024, // 默认 32KB 读缓冲区
		WriteBufferSize:   32 * 1024, // 默认 32KB 写缓冲区
		EnableCompression: true,      // 启用压缩
	}
	// 允许用户覆盖缓冲区配置
	if cfg.WebSocketReadBuffer > 0 {
		dialer.ReadBufferSize = cfg.WebSocketReadBuffer
	}
	if cfg.WebSocketWriteBuffer > 0 {
		dialer.WriteBufferSize = cfg.WebSocketWriteBuffer
	}
	// 如果原始请求有 subprotocol，传递给后端
	if protocols := r.Header.Values("Sec-Websocket-Protocol"); len(protocols) > 0 {
		var subprotocols []string
		for _, p := range protocols {
			// 按逗号分割，并去除空格（Sec-WebSocket-Protocol 可能以逗号分隔多个协议）
			for _, proto := range strings.Split(p, ",") {
				proto = strings.TrimSpace(proto)
				if proto != "" {
					subprotocols = append(subprotocols, proto)
				}
			}
		}
		dialer.Subprotocols = subprotocols
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

	// 升级客户端连接（可按服务覆盖缓冲大小）
	up := wsUpgrader
	if cfg.WebSocketReadBuffer > 0 {
		up.ReadBufferSize = cfg.WebSocketReadBuffer
	}
	if cfg.WebSocketWriteBuffer > 0 {
		up.WriteBufferSize = cfg.WebSocketWriteBuffer
	}
	clientConn, err := up.Upgrade(w, r, responseHeader)
	if err != nil {
		fmt.Printf("WebSocket 客户端升级失败: %v\n", err)
		return
	}
	defer clientConn.Close()

	// 双向转发 WebSocket 消息
	var wg sync.WaitGroup
	wg.Add(2)

	// 客户端 -> 后端
	go func() {
		defer wg.Done()
		for {
			messageType, message, err := clientConn.ReadMessage()
			if err != nil {
				// 关闭后端连接的写端，通知后端不再发送数据
				backendConn.WriteMessage(websocket.CloseMessage,
					websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
				return
			}
			if err := backendConn.WriteMessage(messageType, message); err != nil {
				return
			}
		}
	}()

	// 后端 -> 客户端
	go func() {
		defer wg.Done()
		for {
			messageType, message, err := backendConn.ReadMessage()
			if err != nil {
				// 关闭客户端连接的写端，通知客户端不再发送数据
				clientConn.WriteMessage(websocket.CloseMessage,
					websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
				return
			}
			if err := clientConn.WriteMessage(messageType, message); err != nil {
				return
			}
		}
	}()

	wg.Wait()
	// 两个 goroutine 都已退出，连接将由 defer 关闭
}

// mergeExtendJSON 将 ExtendJSON 中的字段合并到 configData 中（ExtendJSON 优先级高）
func mergeExtendJSON(configData []byte, extendJSON string) []byte {
	if strings.TrimSpace(extendJSON) == "" {
		return configData
	}
	var base map[string]interface{}
	if err := json.Unmarshal(configData, &base); err != nil {
		return configData
	}
	var ext map[string]interface{}
	if err := json.Unmarshal([]byte(extendJSON), &ext); err != nil {
		return configData
	}
	for k, v := range ext {
		base[k] = v
	}
	merged, err := json.Marshal(base)
	if err != nil {
		return configData
	}
	return merged
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
	configData = mergeExtendJSON(configData, service.ExtendJSON)
	if err := json.Unmarshal(configData, &cfg); err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.Root) == "" {
		return nil, fmt.Errorf("静态目录不能为空")
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		relativePath := strings.TrimPrefix(r.URL.Path, "/")
		fullPath := filepath.Join(cfg.Root, filepath.FromSlash(relativePath))

		// 隐藏以.开头的文件/目录
		if cfg.HideDotfiles {
			for _, part := range strings.Split(relativePath, "/") {
				if strings.HasPrefix(part, ".") {
					http.NotFound(w, r)
					return
				}
			}
		}

		info, err := os.Stat(fullPath)
		if err != nil {
			// SPA 模式：请求路径不存在时回退到 index 文件
			if cfg.SPA && os.IsNotExist(err) {
				indexName := strings.TrimSpace(cfg.Index)
				if indexName == "" {
					indexName = "index.html"
				}
				indexPath := filepath.Join(cfg.Root, filepath.FromSlash(indexName))
				if indexInfo, indexErr := os.Stat(indexPath); indexErr == nil && !indexInfo.IsDir() {
					applyStaticResponseHeaders(w, cfg)
					serveStaticFile(w, r, indexPath)
					return
				}
			}
			http.NotFound(w, r)
			return
		}

		// 设置自定义响应头和缓存头
		applyStaticResponseHeaders(w, cfg)

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

// setCacheControlHeader 设置 Cache-Control 响应头
func setCacheControlHeader(header http.Header, cacheMaxAge int) {
	if cacheMaxAge > 0 {
		header.Set("Cache-Control", fmt.Sprintf("public, max-age=%d", cacheMaxAge))
	} else if cacheMaxAge < 0 {
		header.Set("Cache-Control", "no-cache, no-store, must-revalidate")
	}
}

// applyStaticResponseHeaders 设置静态文件响应头（缓存、自定义头）
func applyStaticResponseHeaders(w http.ResponseWriter, cfg models.StaticConfig) {
	setCacheControlHeader(w.Header(), cfg.CacheMaxAge)
	for key, value := range cfg.HeaderDown {
		if value == "" {
			w.Header().Del(key)
		} else {
			w.Header().Set(key, value)
		}
	}
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
	configData = mergeExtendJSON(configData, service.ExtendJSON)
	if err := json.Unmarshal(configData, &cfg); err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.To) == "" {
		return nil, fmt.Errorf("重定向地址不能为空")
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 状态码：优先使用配置値，默认 302 临时重定向
		code := cfg.Code
		if code == 0 {
			code = http.StatusFound
		}
		setCacheControlHeader(w.Header(), cfg.CacheMaxAge)
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
	configData = mergeExtendJSON(configData, service.ExtendJSON)
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
		code := cfg.Code
		if code == 0 {
			code = http.StatusFound
		}
		setCacheControlHeader(w.Header(), cfg.CacheMaxAge)
		http.Redirect(w, r, target, code)
	}), nil
}

// createTextOutputHandler 创建文本输出处理器
func (s *Server) createTextOutputHandler(service models.ServiceConfig) (http.Handler, error) {
	configData, err := json.Marshal(service.Config)
	if err != nil {
		return nil, err
	}

	var cfg models.TextOutputConfig
	configData = mergeExtendJSON(configData, service.ExtendJSON)
	if err := json.Unmarshal(configData, &cfg); err != nil {
		return nil, err
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentType := cfg.ContentType
		if contentType == "" {
			contentType = "text/plain; charset=utf-8"
		}
		// 缓存头（header_down 可覆盖）
		setCacheControlHeader(w.Header(), cfg.CacheMaxAge)
		// 自定义响应头（在 WriteHeader 前设置）
		for key, value := range cfg.HeaderDown {
			if value == "" {
				w.Header().Del(key)
			} else {
				w.Header().Set(key, value)
			}
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
	utils.SetAuthCookie(w, token, utils.RequestIsHTTPS(r), tokenTTL)
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
