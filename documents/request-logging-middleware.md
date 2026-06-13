# 通用请求日志中间件

## 功能说明

`RequestLoggingMiddleware` 是一个最外层的请求日志中间件，记录**所有**到达服务器的HTTP请求，无论成功或失败。

## 特性

### ✅ 记录所有请求
- 成功的请求（2xx, 3xx）
- 失败的请求（4xx, 5xx）
- 被防火墙拦截的请求
- 认证失败的请求
- 路由不存在的请求

### 📊 记录的详细信息

每条日志包含：
- **请求结果**：✓（成功）或 ✗（失败，状态码 >= 400）
- **HTTP方法**：GET, POST, PUT, DELETE 等
- **请求路径**：URL Path
- **状态码**：HTTP Response Status Code
- **耗时**：请求处理时间
- **客户端IP**：真实IP地址（支持 X-Forwarded-For, X-Real-IP）
- **查询参数**：URL Query String（如果有）
- **User-Agent**：客户端标识（截断到100字符）

### 📝 日志格式

```
[请求日志] ✓ GET /api/status 200 1.234ms IP=192.168.0.100 UA=curl/7.88.1
[请求日志] ✗ GET /admin-oauth 401 0.567ms IP=192.168.0.100
[请求日志] ✗ POST /api/users 403 2.345ms IP=10.0.0.1 Query=name=test
```

## 中间件层级

```
请求进入
  ↓
FirewallMiddleware (最外层，优先级最高)
  ↓
RequestLoggingMiddleware (记录所有请求) ← 新增
  ↓
CORSMiddleware
  ↓
FnnasGatewayAuthMiddleware / AuthMiddleware
  ↓
路由处理器
```

## 使用示例

### 启动程序后观察日志

```bash
# 以前台模式运行
./fnproxy \
  -port=sock \
  -socketpath=/vol1/@appcenter/fnproxy-panel/fnproxy.sock \
  -config_path=/vol1/@appdata/fnproxy-panel \
  -secure="你的密钥" \
  -oauth=fnnas \
  -webroot=/app/fnproxy-panel
```

### 测试请求

在另一个终端执行：

```bash
# 测试1：公开接口
curl --unix-socket /vol1/@appcenter/fnproxy-panel/fnproxy.sock \
  http://localhost/api/geoip?ip=8.8.8.8

# 测试2：需要认证的接口
curl --unix-socket /vol1/@appcenter/fnproxy-panel/fnproxy.sock \
  http://localhost/api/status

# 测试3：带飞牛NAS认证Header
curl --unix-socket /vol1/@appcenter/fnproxy-panel/fnproxy.sock \
  -H "X-Trim-Userid: 1000" \
  -H "X-Trim-Username: admin" \
  -H "X-Trim-Isadmin: true" \
  http://localhost/api/status
```

### 预期日志输出

```
[请求日志] ✓ GET /api/geoip 200 2.345ms IP=@ Query=ip=8.8.8.8 UA=curl/7.88.1
[请求日志] ✗ GET /api/status 401 0.123ms IP=@
[请求日志] ✓ GET /api/status 200 1.567ms IP=@ UA=curl/7.88.1
```

## 日志字段说明

| 字段 | 说明 | 示例 |
|------|------|------|
| `✓` / `✗` | 请求结果标记 | ✓ 表示成功，✗ 表示失败 |
| `GET/POST/...` | HTTP方法 | GET, POST, PUT, DELETE |
| `/api/status` | 请求路径 | URL Path |
| `200/401/404` | HTTP状态码 | 200, 301, 401, 403, 404, 500 |
| `1.234ms` | 请求耗时 | 微秒级精度 |
| `IP=192.168.0.1` | 客户端IP | 支持代理透传的真实IP |
| `Query=key=value` | 查询参数 | 仅在有时显示 |
| `UA=curl/7.88.1` | User-Agent | 截断到100字符 |

## Unix Socket 特殊说明

当使用 Unix Socket 时，`RemoteAddr` 可能是 `@` 或空字符串。

日志中会显示：
```
[请求日志] ✓ GET / 200 0.5ms IP=@
```

这表示请求来自本地 Unix Socket 连接。

## 调试技巧

### 1. 实时查看日志

```bash
# 如果程序在前台运行，直接看控制台输出

# 如果重定向到文件
tail -f /vol1/@appdata/fnproxy-panel/stdout.log
```

### 2. 过滤特定类型的请求

```bash
# 只看失败的请求
tail -f stdout.log | grep "✗"

# 只看特定路径
tail -f stdout.log | grep "/api/status"

# 只看特定IP
tail -f stdout.log | grep "IP=192.168.0.100"
```

### 3. 统计请求量

```bash
# 统计总请求数
grep "\[请求日志\]" stdout.log | wc -l

# 统计失败请求数
grep "✗" stdout.log | wc -l

# 统计各状态码数量
grep "\[请求日志\]" stdout.log | awk '{print $5}' | sort | uniq -c
```

## 性能考虑

- ✅ 日志输出使用 `fmt.Println`，性能开销极小
- ✅ 不影响请求处理流程
- ✅ User-Agent 自动截断，避免过长日志
- ⚠️ 高并发场景下建议将日志写入文件而非标准输出

## 与旧日志中间件的区别

### 旧的 LoggingMiddleware
```go
// 只记录方法和路径，没有状态码和IP
fmt.Printf("[%s] %s %s %v\n", time, method, path, duration)
```

### 新的 RequestLoggingMiddleware
```go
// 完整记录：结果、方法、路径、状态码、耗时、IP、查询参数、UA
fmt.Sprintf("[请求日志] %s %s %s %d %v IP=%s Query=%s UA=%s", 
    result, method, path, statusCode, duration, clientIP, query, userAgent)
```

## 故障排查

### 问题1：看不到日志

**原因**：程序在后台运行，标准输出被重定向

**解决**：
```bash
# 方案1：前台运行
./fnproxy ...

# 方案2：重定向到文件
./fnproxy ... > /path/to/logfile.log 2>&1 &
tail -f /path/to/logfile.log
```

### 问题2：日志太多

**解决**：可以按需过滤或关闭

```bash
# 只看错误
tail -f log.log | grep "✗"

# 或者修改代码，只在开发环境启用
if os.Getenv("ENV") == "development" {
    loggedMux = middleware.RequestLoggingMiddleware(mux)
}
```

### 问题3：IP显示为 @

**原因**：Unix Socket 连接的 `RemoteAddr` 是特殊值

**解决**：这是正常现象，表示本地连接。如果需要真实IP，确保飞牛NAS网关传递了 `X-Forwarded-For` Header。

---

## 更新记录

- **2026-06-14**: 创建 RequestLoggingMiddleware，替换旧的简单日志中间件
- **2026-06-14**: 放置在防火墙之后，确保记录所有请求
