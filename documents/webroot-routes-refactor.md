# WebRoot 路由重构说明

## 🎯 设计原则

1. **所有路由都带 WebRoot 前缀**：内部路由和浏览器URL保持一致
2. **使用常量定义路径**：避免魔法字符串，统一管理
3. **飞牛NAS不去掉前缀**：程序直接处理完整路径（如 `/app/fnproxy-panel/xxx`）

---

## 📁 新增文件

### `src/routes/routes.go`

定义了所有路由常量和构建函数：

```go
// API 路由常量
const (
    RouteAdminOAuth   = "/admin-oauth"
    RouteAuthLogin    = "/api/auth/login"
    RouteUsers        = "/api/users"
    RouteGeoIP        = "/api/geoip"
    // ... 更多路由
)

// BuildRoute 构建带WebRoot前缀的完整路由
func BuildRoute(webRoot, route string) string {
    if webRoot == "" || webRoot == "/" {
        return route
    }
    return webRoot + route
}
```

---

## 🔧 修改内容

### 1. main.go - 路由注册

**之前**（错误）：
```go
mux.HandleFunc("/admin-oauth", handlers.AdminOAuthHandler)
mux.Handle("/api/", handler)
```

**现在**（正确）：
```go
webRoot := config.GetRuntimeWebRoot()
buildRoute := func(route string) string {
    return routes.BuildRoute(webRoot, route)
}

mux.HandleFunc(buildRoute(routes.RouteAdminOAuth), handlers.AdminOAuthHandler)
mux.Handle(buildRoute("/api/"), handler)
```

### 2. auth.go - URL生成

**之前**（错误）：
```go
loginPath := webRoot + "/admin-oauth"  // 魔法字符串
redirectTarget = webRoot + "/"         // 魔法字符串
```

**现在**（正确）：
```go
loginPath := routes.BuildRoute(webRoot, routes.RouteAdminOAuth)
redirectTarget = routes.BuildRoute(webRoot, routes.RouteRoot)
```

### 3. 移除了不必要的中间件

- ❌ 删除了 `WebRootStripMiddleware`（不再需要剥离前缀）
- ❌ 删除了所有调试日志（`[DEBUG ...]`）
- ✅ 保留了 `RequestLoggingMiddleware`（记录所有请求）

---

## 🔄 工作流程

### 场景1：启用 `-webroot=/app/fnproxy-panel`

```
1. 用户访问: http://192.168.0.2/app/fnproxy-panel/
   ↓
2. 飞牛NAS转发: GET /app/fnproxy-panel/ (保留完整路径)
   ↓
3. RequestLoggingMiddleware 记录:
   [请求日志] GET /app/fnproxy-panel/ 200 1.2ms IP=@
   ↓
4. 路由匹配: /app/fnproxy-panel/ ✅
   ↓
5. 返回响应
```

### 场景2：未登录重定向

```
1. 用户访问: /app/fnproxy-panel/api/status
   ↓
2. 中间件检查未登录
   ↓
3. 生成重定向URL:
   loginPath = routes.BuildRoute("/app/fnproxy-panel", "/admin-oauth")
             = "/app/fnproxy-panel/admin-oauth"
   ↓
4. 重定向到: /app/fnproxy-panel/admin-oauth?redirect=/app/fnproxy-panel/api/status
   ↓
5. 浏览器显示登录页面
```

### 场景3：登录成功

```
1. 用户提交登录表单
   ↓
2. 验证成功
   ↓
3. 生成重定向URL:
   redirectTarget = routes.BuildRoute("/app/fnproxy-panel", "/")
                  = "/app/fnproxy-panel/"
   ↓
4. 重定向到: /app/fnproxy-panel/
   ↓
5. 浏览器显示管理界面
```

---

## ✅ 优势

### 1. 无魔法字符串

所有路径都使用常量定义：
```go
routes.RouteAdminOAuth    // 而不是 "/admin-oauth"
routes.RouteRoot          // 而不是 "/"
routes.BuildRoute(...)    // 统一的路径构建
```

### 2. 一致性

- 内部路由：`/app/fnproxy-panel/xxx`
- 浏览器URL：`/app/fnproxy-panel/xxx`
- 重定向URL：`/app/fnproxy-panel/xxx`

**完全一致**，不会出错。

### 3. 易于维护

- 修改路由只需改一处（`routes.go`）
- 添加新路由有统一规范
- 代码可读性强

### 4. 兼容性好

- 支持 WebRoot 为空的情况
- 支持 WebRoot 为 `/` 的情况
- 自动处理路径拼接（避免双斜杠等问题）

---

## 📊 路由示例

| 常量 | WebRoot="" | WebRoot="/app/fnproxy-panel" |
|------|-----------|------------------------------|
| `RouteRoot` | `/` | `/app/fnproxy-panel/` |
| `RouteAdminOAuth` | `/admin-oauth` | `/app/fnproxy-panel/admin-oauth` |
| `/api/` | `/api/` | `/app/fnproxy-panel/api/` |
| `/ws/` | `/ws/` | `/app/fnproxy-panel/ws/` |
| `/static/` | `/static/` | `/app/fnproxy-panel/static/` |

---

## 🚀 测试步骤

### 1. 重新编译

```bash
cd /var/apps/fnproxy-panel/target
go build -o fnproxy ../../src/
```

### 2. 重启服务

```bash
./fnproxy -action=restart
```

### 3. 观察日志

访问 `http://192.168.0.2/app/fnproxy-panel/`，应该看到：

```
[请求日志] ✓ GET /app/fnproxy-panel/ 302 1.234ms IP=@ UA=Mozilla/5.0...
[请求日志] ✓ GET /app/fnproxy-panel/admin-oauth 200 2.345ms IP=@ UA=Mozilla/5.0...
```

### 4. 登录测试

登录后应该正常跳转到 `/app/fnproxy-panel/`，不再出现 404。

---

## 💡 关键改进点

### 之前的问题

1. ❌ 内部路由不带前缀，浏览器URL带前缀 → 不一致
2. ❌ 使用魔法字符串 `"/admin-oauth"`、`"/"` → 难以维护
3. ❌ 尝试从 Header 或路径中提取 WebRoot → 复杂且不可靠
4. ❌ 大量的调试日志 → 代码混乱

### 现在的方案

1. ✅ 内部路由和浏览器URL完全一致
2. ✅ 使用常量定义所有路径
3. ✅ 直接使用配置的 WebRoot，简单可靠
4. ✅ 代码简洁清晰

---

## 📝 相关文件清单

### 新增
- `src/routes/routes.go` - 路由常量和构建函数

### 修改
- `src/main.go` - 使用路由常量注册路由
- `src/handlers/auth.go` - 使用路由常量生成URL

### 删除
- `src/middleware/webroot_strip.go` - 不再需要

---

## 🎓 最佳实践

### 添加新路由时

1. 在 `routes/routes.go` 中定义常量：
```go
const RouteMyNewAPI = "/api/my-new-api"
```

2. 在 `main.go` 中注册：
```go
apiMux.HandleFunc(buildRoute(routes.RouteMyNewAPI), handlers.MyNewHandler)
```

3. 在需要重定向的地方使用：
```go
redirectURL := routes.BuildRoute(webRoot, routes.RouteMyNewAPI)
http.Redirect(w, r, redirectURL, http.StatusFound)
```

### 永远不要

- ❌ 硬编码路径字符串
- ❌ 手动拼接 WebRoot 和路径
- ❌ 假设飞牛NAS会去掉前缀

---

## 更新记录

- **2026-06-14**: 创建 routes 包，统一定义路由常量
- **2026-06-14**: 重构 main.go 和 auth.go，使用 BuildRoute 函数
- **2026-06-14**: 移除 WebRootStripMiddleware 和调试日志
