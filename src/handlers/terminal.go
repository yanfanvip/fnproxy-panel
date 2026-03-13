package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"caddy-panel/config"
	"caddy-panel/models"
	"caddy-panel/security"
	"caddy-panel/utils"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

const (
	terminalBufferLimit       = 256 * 1024
	terminalAttachedTTL       = 90 * time.Second
	terminalDetachedRetention = 30 * time.Minute
	terminalJanitorInterval   = 1 * time.Minute
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// TerminalSession 终端会话
type TerminalSession struct {
	ID            string
	Owner         string
	Connection    models.SSHConnection
	Stdin         io.WriteCloser
	Stdout        io.Reader
	Stderr        io.Reader
	LocalCmd      *exec.Cmd
	SSHClient     *ssh.Client
	SSHSession    *ssh.Session
	CreatedAt     time.Time
	LastHeartbeat time.Time
	DetachedAt    time.Time
	Attached      bool
	Status        string
	buffer        []byte
	done          chan struct{}
	closeOnce     sync.Once
	mu            sync.Mutex
	wsMu          sync.Mutex
	attachedConn  *websocket.Conn
}

var (
	sessions        = make(map[string]*TerminalSession)
	sessionsMu      sync.RWMutex
	terminalJanitor sync.Once
)

// ListSSHConnectionsHandler 获取SSH连接列表
func ListSSHConnectionsHandler(w http.ResponseWriter, r *http.Request) {
	items := config.GetManager().GetSSHConnections()
	for i := range items {
		items[i].Password = ""
	}
	WriteSuccess(w, items)
}

// CreateSSHConnectionHandler 创建SSH连接
func CreateSSHConnectionHandler(w http.ResponseWriter, r *http.Request) {
	var conn models.SSHConnection
	if err := json.NewDecoder(r.Body).Decode(&conn); err != nil {
		WriteError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	conn.ID = uuid.NewString()
	conn.CreatedAt = time.Now()
	conn.UpdatedAt = time.Now()
	if conn.IsLocal {
		conn.Host = "localhost"
		if conn.Port == 0 {
			conn.Port = 22
		}
	}
	if conn.Port == 0 {
		conn.Port = 22
	}
	if conn.Name == "" {
		if conn.IsLocal {
			conn.Name = "本机连接"
		} else {
			conn.Name = fmt.Sprintf("%s:%d", conn.Host, conn.Port)
		}
	}
	if conn.Password != "" {
		plainPassword, err := decryptIncomingPassword(conn.Password)
		if err != nil {
			WriteError(w, http.StatusBadRequest, "SSH 密码解密失败")
			return
		}
		encryptedPassword, err := security.EncryptSecretValue(plainPassword)
		if err != nil {
			WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		conn.Password = encryptedPassword
	}

	if err := config.GetManager().AddSSHConnection(conn); err != nil {
		WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// 记录安全日志
	opUser, opAddr := getRequestContext(r)
	security.GetAuditLogger().LogSystemOperate(opUser, opAddr, "新增SSH连接", conn.Name, fmt.Sprintf("新增SSH连接: %s (%s@%s:%d)", conn.Name, conn.Username, conn.Host, conn.Port), true, nil)

	conn.Password = ""
	WriteSuccess(w, conn)
}

// UpdateSSHConnectionHandler 更新SSH连接
func UpdateSSHConnectionHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/api/ssh-connections/"):]

	var conn models.SSHConnection
	if err := json.NewDecoder(r.Body).Decode(&conn); err != nil {
		WriteError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	current := config.GetManager().GetSSHConnection(id)
	if current == nil {
		WriteError(w, http.StatusNotFound, "SSH connection not found")
		return
	}

	conn.ID = id
	conn.CreatedAt = current.CreatedAt
	conn.UpdatedAt = time.Now()
	if conn.IsLocal {
		conn.Host = "localhost"
		if conn.Port == 0 {
			conn.Port = 22
		}
		conn.Username = ""
	}
	if conn.Port == 0 {
		conn.Port = current.Port
		if conn.Port == 0 {
			conn.Port = 22
		}
	}
	if strings.TrimSpace(conn.Name) == "" {
		conn.Name = current.Name
	}
	if strings.TrimSpace(conn.WorkDir) == "" {
		conn.WorkDir = current.WorkDir
	}
	if !conn.IsLocal && strings.TrimSpace(conn.Host) == "" {
		conn.Host = current.Host
	}
	if !conn.IsLocal && strings.TrimSpace(conn.Username) == "" {
		conn.Username = current.Username
	}
	if conn.Password == "" {
		conn.Password = current.Password
	} else {
		plainPassword, err := decryptIncomingPassword(conn.Password)
		if err != nil {
			WriteError(w, http.StatusBadRequest, "SSH 密码解密失败")
			return
		}
		encryptedPassword, err := security.EncryptSecretValue(plainPassword)
		if err != nil {
			WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		conn.Password = encryptedPassword
	}

	if err := config.GetManager().UpdateSSHConnection(conn); err != nil {
		WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// 记录安全日志
	opUser, opAddr := getRequestContext(r)
	security.GetAuditLogger().LogSystemOperate(opUser, opAddr, "修改SSH连接", conn.Name, fmt.Sprintf("修改SSH连接: %s", conn.Name), true, nil)

	conn.Password = ""
	WriteSuccess(w, conn)
}

// DeleteSSHConnectionHandler 删除SSH连接
func DeleteSSHConnectionHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/api/ssh-connections/"):]
	conn := config.GetManager().GetSSHConnection(id)
	if err := config.GetManager().DeleteSSHConnection(id); err != nil {
		WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// 记录安全日志
	opUser, opAddr := getRequestContext(r)
	connName := id
	if conn != nil {
		connName = conn.Name
	}
	security.GetAuditLogger().LogSystemOperate(opUser, opAddr, "删除SSH连接", connName, fmt.Sprintf("删除SSH连接: %s", connName), true, nil)

	WriteSuccess(w, nil)
}

// GetSSHConnectionHandler 获取单个SSH连接
func GetSSHConnectionHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/api/ssh-connections/"):]
	conn := config.GetManager().GetSSHConnection(id)
	if conn == nil {
		WriteError(w, http.StatusNotFound, "SSH connection not found")
		return
	}
	safeConn := *conn
	safeConn.Password = ""
	WriteSuccess(w, safeConn)
}

// TestSSHConnectionHandler 测试SSH连接
func TestSSHConnectionHandler(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSuffix(r.URL.Path[len("/api/ssh-connections/"):], "/test")
	conn := config.GetManager().GetSSHConnection(id)
	if conn == nil {
		WriteError(w, http.StatusNotFound, "SSH connection not found")
		return
	}

	if conn.IsLocal {
		shell := getShell()
		if _, err := exec.LookPath(shell); err != nil {
			WriteError(w, http.StatusInternalServerError, "本机终端不可用")
			return
		}
		if strings.TrimSpace(conn.WorkDir) != "" {
			if info, err := os.Stat(conn.WorkDir); err != nil || !info.IsDir() {
				WriteError(w, http.StatusBadRequest, "默认工作目录不存在或不可访问")
				return
			}
		}
		WriteSuccessWithMessage(w, nil, "本机终端检查通过")
		return
	}

	client, session, _, _, _, err := createSSHClient(*conn)
	if err != nil {
		WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if session != nil {
		_ = session.Close()
	}
	if client != nil {
		_ = client.Close()
	}
	WriteSuccessWithMessage(w, nil, "SSH 连接测试成功")
}

// ListTerminalSessionsHandler 获取当前用户的终端会话
func ListTerminalSessionsHandler(w http.ResponseWriter, r *http.Request) {
	WriteSuccess(w, listTerminalSessionsByOwner(getTerminalOwner(r)))
}

// CreateTerminalSessionHandler 创建托管终端会话
func CreateTerminalSessionHandler(w http.ResponseWriter, r *http.Request) {
	ensureTerminalJanitor()

	remoteAddr := r.RemoteAddr
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		remoteAddr = strings.Split(xff, ",")[0]
	}
	username := getTerminalOwner(r)

	var req struct {
		ConnectionID string `json:"connection_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.ConnectionID == "" {
		WriteError(w, http.StatusBadRequest, "connection_id is required")
		return
	}

	conn := config.GetManager().GetSSHConnection(req.ConnectionID)
	if conn == nil {
		security.GetAuditLogger().LogSSHConnect(username, remoteAddr, req.ConnectionID, false, "SSH连接配置不存在")
		WriteError(w, http.StatusNotFound, "SSH connection not found")
		return
	}

	session, err := createManagedTerminalSession(username, *conn)
	if err != nil {
		security.GetAuditLogger().LogSSHConnect(username, remoteAddr, conn.Name, false, err.Error())
		WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	security.GetAuditLogger().LogSSHConnect(username, remoteAddr, conn.Name, true, fmt.Sprintf("连接到 %s@%s:%d", conn.Username, conn.Host, conn.Port))
	WriteSuccess(w, session.snapshot())
}

// DeleteTerminalSessionHandler 关闭终端会话
func DeleteTerminalSessionHandler(w http.ResponseWriter, r *http.Request) {
	remoteAddr := r.RemoteAddr
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		remoteAddr = strings.Split(xff, ",")[0]
	}
	username := getTerminalOwner(r)

	id := terminalSessionIDFromPath(r.URL.Path)
	session := getTerminalSessionForOwner(id, username)
	if session == nil {
		WriteError(w, http.StatusNotFound, "Terminal session not found")
		return
	}
	connName := session.Connection.Name
	session.Close()
	security.GetAuditLogger().LogSSHDisconnect(username, remoteAddr, connName, "主动关闭终端会话")
	WriteSuccess(w, nil)
}

// TerminalHeartbeatHandler 刷新会话心跳
func TerminalHeartbeatHandler(w http.ResponseWriter, r *http.Request) {
	id := terminalSessionIDFromPath(strings.TrimSuffix(r.URL.Path, "/heartbeat"))
	session := getTerminalSessionForOwner(id, getTerminalOwner(r))
	if session == nil {
		WriteError(w, http.StatusNotFound, "Terminal session not found")
		return
	}
	session.Touch()
	WriteSuccess(w, session.snapshot())
}

// TerminalHandler WebSocket终端处理器
func TerminalHandler(w http.ResponseWriter, r *http.Request) {
	ensureTerminalJanitor()

	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		WriteError(w, http.StatusBadRequest, "session_id is required")
		return
	}

	session := getTerminalSessionForOwner(sessionID, getTerminalOwner(r))
	if session == nil {
		WriteError(w, http.StatusNotFound, "Terminal session not found")
		return
	}

	wsConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "Failed to upgrade connection")
		return
	}

	session.Attach(wsConn)
	handleInput(session, wsConn)
}

func createManagedTerminalSession(owner string, conn models.SSHConnection) (*TerminalSession, error) {
	session := &TerminalSession{
		ID:            generateSessionID(),
		Owner:         owner,
		Connection:    conn,
		CreatedAt:     time.Now(),
		LastHeartbeat: time.Now(),
		DetachedAt:    time.Now(),
		Status:        "connecting",
		done:          make(chan struct{}),
	}

	if conn.IsLocal {
		cmd := exec.Command(getShell())
		if conn.WorkDir != "" {
			cmd.Dir = conn.WorkDir
		}
		stdin, err := cmd.StdinPipe()
		if err != nil {
			return nil, fmt.Errorf("failed to create stdin pipe")
		}
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return nil, fmt.Errorf("failed to create stdout pipe")
		}
		stderr, err := cmd.StderrPipe()
		if err != nil {
			return nil, fmt.Errorf("failed to create stderr pipe")
		}
		if err := cmd.Start(); err != nil {
			return nil, fmt.Errorf("failed to start shell")
		}

		session.Stdin = stdin
		session.Stdout = stdout
		session.Stderr = stderr
		session.LocalCmd = cmd
		session.Status = "running"

		go func() {
			_ = cmd.Wait()
			session.Close()
		}()
	} else {
		client, sshSession, stdin, stdout, stderr, err := createSSHClient(conn)
		if err != nil {
			return nil, err
		}
		session.SSHClient = client
		session.SSHSession = sshSession
		session.Stdin = stdin
		session.Stdout = stdout
		session.Stderr = stderr
		session.Status = "running"

		go func() {
			_ = sshSession.Wait()
			session.Close()
		}()
	}

	registerTerminalSession(session)
	go handleOutput(session, session.Stdout, "stdout")
	go handleOutput(session, session.Stderr, "stderr")
	return session, nil
}

func createSSHClient(conn models.SSHConnection) (*ssh.Client, *ssh.Session, io.WriteCloser, io.Reader, io.Reader, error) {
	password, err := security.DecryptSecretValue(conn.Password)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	cfg := &ssh.ClientConfig{
		User: conn.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         8 * time.Second,
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", conn.Host, conn.Port), cfg)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("SSH连接失败: %w", err)
	}

	session, err := client.NewSession()
	if err != nil {
		_ = client.Close()
		return nil, nil, nil, nil, nil, fmt.Errorf("创建SSH会话失败: %w", err)
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		_ = session.Close()
		_ = client.Close()
		return nil, nil, nil, nil, nil, fmt.Errorf("创建SSH输入失败")
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		_ = session.Close()
		_ = client.Close()
		return nil, nil, nil, nil, nil, fmt.Errorf("创建SSH输出失败")
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		_ = session.Close()
		_ = client.Close()
		return nil, nil, nil, nil, nil, fmt.Errorf("创建SSH错误输出失败")
	}

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := session.RequestPty("xterm-256color", 32, 120, modes); err != nil {
		_ = session.Close()
		_ = client.Close()
		return nil, nil, nil, nil, nil, fmt.Errorf("申请终端失败: %w", err)
	}
	if err := session.Shell(); err != nil {
		_ = session.Close()
		_ = client.Close()
		return nil, nil, nil, nil, nil, fmt.Errorf("启动远程Shell失败: %w", err)
	}
	if conn.WorkDir != "" {
		_, _ = stdin.Write([]byte(fmt.Sprintf("cd %q\n", conn.WorkDir)))
	}

	return client, session, stdin, stdout, stderr, nil
}

// handleInput 处理WebSocket输入
func handleInput(session *TerminalSession, wsConn *websocket.Conn) {
	for {
		select {
		case <-session.done:
			return
		default:
			var msg map[string]interface{}
			if err := wsConn.ReadJSON(&msg); err != nil {
				session.Detach(wsConn)
				return
			}

			msgType, ok := msg["type"].(string)
			if !ok {
				continue
			}

			switch msgType {
			case "input":
				if data, ok := msg["data"].(string); ok {
					session.mu.Lock()
					_, _ = session.Stdin.Write([]byte(data))
					session.mu.Unlock()
					session.Touch()
				}
			case "resize":
				cols, _ := msg["cols"].(float64)
				rows, _ := msg["rows"].(float64)
				resizeTerminal(session, int(cols), int(rows))
				session.Touch()
			case "ping":
				session.Touch()
				_ = session.writeToConn(wsConn, map[string]string{"type": "pong"})
			case "close":
				session.Detach(wsConn)
				return
			}
		}
	}
}

// handleOutput 处理命令输出
func handleOutput(session *TerminalSession, reader io.Reader, streamType string) {
	if reader == nil {
		return
	}

	buf := make([]byte, 2048)
	for {
		select {
		case <-session.done:
			return
		default:
			n, err := reader.Read(buf)
			if err != nil {
				if err != io.EOF {
					session.emit("error", err.Error())
					session.Close()
				}
				return
			}

			if n > 0 {
				session.emit(streamType, string(buf[:n]))
			}
		}
	}
}

func (s *TerminalSession) emit(msgType, data string) {
	s.mu.Lock()
	if msgType == "stdout" || msgType == "stderr" {
		s.buffer = append(s.buffer, []byte(data)...)
		if len(s.buffer) > terminalBufferLimit {
			s.buffer = append([]byte(nil), s.buffer[len(s.buffer)-terminalBufferLimit:]...)
		}
	}
	conn := s.attachedConn
	s.mu.Unlock()

	if conn != nil {
		_ = s.writeToConn(conn, map[string]string{
			"type": msgType,
			"data": data,
		})
	}
}

func (s *TerminalSession) writeToConn(conn *websocket.Conn, payload interface{}) error {
	if conn == nil {
		return nil
	}
	s.wsMu.Lock()
	defer s.wsMu.Unlock()
	if err := conn.WriteJSON(payload); err != nil {
		s.Detach(conn)
		return err
	}
	return nil
}

func (s *TerminalSession) Attach(conn *websocket.Conn) {
	s.mu.Lock()
	oldConn := s.attachedConn
	s.attachedConn = conn
	s.Attached = true
	s.DetachedAt = time.Time{}
	s.LastHeartbeat = time.Now()
	info := s.snapshotLocked()
	bufferSnapshot := string(s.buffer)
	s.mu.Unlock()

	if oldConn != nil && oldConn != conn {
		_ = oldConn.Close()
	}

	_ = s.writeToConn(conn, map[string]interface{}{
		"type":        "connected",
		"session_id":  info.ID,
		"connection":  info.Name,
		"is_local":    info.IsLocal,
		"working_dir": info.WorkDir,
		"attached":    info.Attached,
		"status":      info.Status,
	})
	if bufferSnapshot != "" {
		_ = s.writeToConn(conn, map[string]string{
			"type": "stdout",
			"data": bufferSnapshot,
		})
	}
}

func (s *TerminalSession) Detach(conn *websocket.Conn) {
	s.mu.Lock()
	if conn == nil || s.attachedConn == conn {
		s.attachedConn = nil
		s.Attached = false
		s.DetachedAt = time.Now()
	}
	s.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
}

func (s *TerminalSession) Touch() {
	s.mu.Lock()
	s.LastHeartbeat = time.Now()
	s.mu.Unlock()
}

func (s *TerminalSession) snapshot() models.TerminalManagedSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshotLocked()
}

func (s *TerminalSession) snapshotLocked() models.TerminalManagedSession {
	return models.TerminalManagedSession{
		ID:            s.ID,
		ConnectionID:  s.Connection.ID,
		Name:          s.Connection.Name,
		Host:          s.Connection.Host,
		Port:          s.Connection.Port,
		Username:      s.Connection.Username,
		WorkDir:       s.Connection.WorkDir,
		IsLocal:       s.Connection.IsLocal,
		Attached:      s.Attached,
		Status:        s.Status,
		CreatedAt:     s.CreatedAt,
		LastHeartbeat: s.LastHeartbeat,
	}
}

func (s *TerminalSession) isStale(now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Status == "closed" {
		return false
	}
	if s.Attached {
		return now.Sub(s.LastHeartbeat) > terminalAttachedTTL
	}
	return now.Sub(s.LastHeartbeat) > terminalDetachedRetention
}

func registerTerminalSession(session *TerminalSession) {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	sessions[session.ID] = session
}

func unregisterTerminalSession(id string) {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	delete(sessions, id)
}

func listTerminalSessionsByOwner(owner string) []models.TerminalManagedSession {
	sessionsMu.RLock()
	defer sessionsMu.RUnlock()

	items := make([]models.TerminalManagedSession, 0, len(sessions))
	for _, session := range sessions {
		if session.Owner == owner {
			items = append(items, session.snapshot())
		}
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].CreatedAt.Before(items[j].CreatedAt)
	})
	return items
}

func getTerminalSessionForOwner(id, owner string) *TerminalSession {
	sessionsMu.RLock()
	defer sessionsMu.RUnlock()
	session := sessions[id]
	if session == nil || session.Owner != owner {
		return nil
	}
	return session
}

func ensureTerminalJanitor() {
	terminalJanitor.Do(func() {
		go func() {
			ticker := time.NewTicker(terminalJanitorInterval)
			defer ticker.Stop()
			for range ticker.C {
				now := time.Now()
				sessionsMu.RLock()
				items := make([]*TerminalSession, 0, len(sessions))
				for _, session := range sessions {
					items = append(items, session)
				}
				sessionsMu.RUnlock()
				for _, session := range items {
					if session.isStale(now) {
						session.Close()
					}
				}
			}
		}()
	})
}

func terminalSessionIDFromPath(path string) string {
	id := strings.TrimPrefix(path, "/api/terminal-sessions/")
	if idx := strings.IndexRune(id, '/'); idx >= 0 {
		return id[:idx]
	}
	return id
}

func getTerminalOwner(r *http.Request) string {
	if claims, ok := r.Context().Value("claims").(*utils.Claims); ok && claims != nil && claims.Username != "" {
		return claims.Username
	}
	if claims, err := utils.GetAuthClaimsFromRequest(r); err == nil && claims != nil && claims.Username != "" {
		return claims.Username
	}
	return "anonymous"
}

// resizeTerminal 调整终端大小
func resizeTerminal(session *TerminalSession, cols, rows int) {
	if rows <= 0 || cols <= 0 {
		return
	}

	if session.SSHSession != nil {
		_ = session.SSHSession.WindowChange(rows, cols)
		return
	}

	if runtime.GOOS == "windows" {
		return
	}

	cmd := exec.Command("stty", "rows", fmt.Sprintf("%d", rows), "cols", fmt.Sprintf("%d", cols))
	_ = cmd.Run()
}

// getShell 获取系统shell
func getShell() string {
	switch runtime.GOOS {
	case "windows":
		if _, err := os.Stat(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`); err == nil {
			return `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
		}
		return "cmd.exe"
	case "darwin":
		return "/bin/zsh"
	default:
		return "/bin/bash"
	}
}

// generateSessionID 生成会话ID
func generateSessionID() string {
	return fmt.Sprintf("term_%d", time.Now().UnixNano())
}

// Close 关闭会话
func (s *TerminalSession) Close() {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.Status = "closed"
		conn := s.attachedConn
		s.attachedConn = nil
		s.Attached = false
		s.mu.Unlock()

		if s.LocalCmd != nil && s.LocalCmd.Process != nil {
			_ = s.LocalCmd.Process.Kill()
		}
		if s.SSHSession != nil {
			_ = s.SSHSession.Close()
		}
		if s.SSHClient != nil {
			_ = s.SSHClient.Close()
		}
		if conn != nil {
			_ = conn.Close()
		}
		unregisterTerminalSession(s.ID)
		close(s.done)
	})
}

// CloseAllSessions 关闭所有终端会话
func CloseAllSessions() {
	sessionsMu.RLock()
	items := make([]*TerminalSession, 0, len(sessions))
	for _, session := range sessions {
		items = append(items, session)
	}
	sessionsMu.RUnlock()

	for _, session := range items {
		session.Close()
	}
}
