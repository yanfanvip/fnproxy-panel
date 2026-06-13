# 飞牛NAS网关认证集成 - 实现总结

## 修改概述

本次更新为FnProxy添加了飞牛NAS统一网关认证支持。通过 `-oauth=fnnas` 启动参数，可以将后台管理界面的认证方式切换为飞牛NAS网关认证模式。

## 文件修改清单

### 1. 新增文件

#### `src/middleware/fnnas_auth.go`
- **功能**：飞牛NAS网关认证中间件
- **主要函数**：
  - `FnnasGatewayAuthMiddleware()` - 从网关Header中提取用户信息并认证
  - `FnnasAdminMiddleware()` - 检查管理员权限
  - `GetFnnasUserInfo()` - 获取飞牛NAS用户信息工具函数

#### `documents/fnnas-oauth-integration.md`
- **功能**：详细的使用文档和集成指南

#### `test-fnnas-oauth.bat`
- **功能**：测试脚本，展示不同的启动方式

### 2. 修改文件

#### `src/main.go`
**修改内容**：
1. 添加 `-oauth` 启动参数解析
2. 调用 `config.SetRuntimeOAuthMode()` 设置OAuth模式
3. 根据OAuth模式动态选择认证中间件：
   - 飞牛NAS模式：使用 `FnnasGatewayAuthMiddleware`
   - 传统模式：使用 `AuthMiddleware`

**关键代码**：
```go
oauthArg := flag.String("oauth", "", "OAuth 认证模式：fnnas 表示使用飞牛NAS网关认证")
// ...
if config.IsRuntimeOAuthFnnas() {
    handler = middleware.FnnasGatewayAuthMiddleware(handler)
} else {
    handler = middleware.AuthMiddleware(handler)
}
```

#### `src/config/runtime_paths.go`
**修改内容**：
1. 添加 `runtimeOAuthMode` 变量存储OAuth模式
2. 新增函数：
   - `SetRuntimeOAuthMode(mode string)` - 设置OAuth模式
   - `GetRuntimeOAuthMode() string` - 获取OAuth模式
   - `IsRuntimeOAuthFnnas() bool` - 检查是否为飞牛NAS模式

**关键代码**：
```go
func IsRuntimeOAuthFnnas() bool {
    return GetRuntimeOAuthMode() == "fnnas"
}
```

#### `src/middleware/auth.go`
**修改内容**：
1. 导入 `fnproxy/config` 包
2. 修改 `isPublicPath()` 函数，在飞牛NAS模式下禁用登录相关接口

**关键逻辑**：
```go
if config.IsRuntimeOAuthFnnas() {
    // 仅保留真正公开的接口（如GeoIP）
    publicPaths := []string{"/api/geoip"}
    // ...
}
```

#### `src/handlers/auth.go`
**修改内容**：
1. `LoginHandler()` - 飞牛NAS模式下返回403错误，禁用传统登录
2. `AdminOAuthHandler()` - 飞牛NAS模式下返回403错误，禁用本地登录页面
3. `GetCurrentUserHandler()` - 飞牛NAS模式下直接返回claims信息，不查询数据库
4. `AdminPageAuthMiddleware()` - 飞牛NAS模式下不进行重定向，直接返回401

**关键逻辑**：
```go
// LoginHandler 中
if config.IsRuntimeOAuthFnnas() {
    WriteError(w, http.StatusForbidden, "当前使用飞牛NAS网关认证，不支持传统登录")
    return
}
```

## 技术实现细节

### 认证流程对比

#### 传统模式
```
客户端请求 
  → AuthMiddleware 检查 JWT Token 
  → 验证Token签名和有效期 
  → 从数据库加载用户信息 
  → 将Claims注入Context 
  → 业务Handler处理
```

#### 飞牛NAS模式
```
客户端请求（经飞牛NAS网关）
  → 飞牛NAS验证用户登录态
  → 网关添加 X-Trim-* Headers
  → FnnasGatewayAuthMiddleware 读取Headers
  → **检查是否为管理员**（非管理员直接拒绝）
  → 构建Claims（基于Header信息）
  → 将Claims注入Context
  → 业务Handler处理
```

### Header映射关系

| 飞牛NAS Header | Claims字段 | 说明 |
|----------------|-----------|------|
| `X-Trim-Username` | `claims.Username` | 用户名 |
| `X-Trim-Isadmin=true` | `claims.Role="admin"` | **仅管理员可访问** |
| `X-Trim-Isadmin=false` | - | **直接拒绝，返回403** |
| `X-Trim-Userid` | （可用于数据隔离） | 用户UID |

**重要安全策略**：
- 管理端**仅允许** `X-Trim-Isadmin=true` 的用户访问
- 普通用户（`X-Trim-Isadmin=false`）会被立即拒绝，返回 403 Forbidden

### 权限控制

系统继续使用现有的权限中间件机制：
- `AdminMiddleware` / `FnnasAdminMiddleware` - 检查管理员权限
- 基于 `claims.Role` 字段判断

## 兼容性说明

### ✅ 向后兼容

1. **默认行为不变**：不指定 `-oauth` 参数时，使用传统的JWT认证
2. **配置不变**：所有现有配置项保持不变
3. **API不变**：除登录相关API外，其他API行为一致

### ⚠️  breaking changes（当启用飞牛NAS模式时）

1. `/api/login` 接口返回403
2. `/admin-oauth` 页面返回403
3. 不再使用本地用户数据库进行认证
4. 必须通过飞牛NAS网关访问

## 安全考虑

### 已实现的安全措施

1. **双重验证**：
   - 飞牛NAS网关验证用户登录态
   - 应用层验证用户权限

2. **Header信任**：
   - 仅信任网关透传的Header
   - 不信任客户端主动上报的用户ID

3. **权限最小化**：
   - 公开接口最小化（仅GeoIP）
   - 管理员功能需要额外校验

### 建议的安全实践

1. **网络隔离**：确保应用只能通过飞牛NAS网关访问
2. **防火墙规则**：阻止直接访问应用端口
3. **日志审计**：记录所有管理操作
4. **定期更新**：保持系统和依赖库最新

## 测试建议

### 单元测试场景

1. **传统模式测试**
   - 使用JWT Token访问API
   - 验证登录/登出功能
   - 检查用户管理功能

2. **飞牛NAS模式测试**
   - 模拟网关Header发送请求
   - 验证用户信息正确提取
   - 检查管理员权限判断
   - 确认登录接口被禁用

3. **边界情况**
   - 缺少必需Header时的处理
   - 无效的Header值处理
   - WebSocket连接的认证

### 集成测试场景

1. 通过飞牛NAS网关访问应用
2. 普通用户和管理员用户的权限差异
3. 会话保持和超时处理
4. 并发请求的处理

## 部署指南

### 开发环境

```bash
# 传统模式
./fnproxy -port=8080

# 飞牛NAS模式（需要网关环境）
./fnproxy -port=8080 -oauth=fnnas
```

### 生产环境

```bash
# 推荐配置
./fnproxy \
  -config_path=/opt/fnproxy \
  -port=8080 \
  -oauth=fnnas \
  -secure="production-secret-key"
```

### Docker部署

```dockerfile
FROM golang:1.26-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o fnproxy ./src

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/fnproxy .
EXPOSE 8080
ENTRYPOINT ["./fnproxy", "-oauth=fnnas"]
```

## 后续优化建议

1. **缓存优化**：缓存用户信息，减少重复解析
2. **监控增强**：添加飞牛NAS认证相关的监控指标
3. **降级策略**：网关不可用时的降级处理
4. **多租户支持**：支持多个飞牛NAS实例
5. **Webhook通知**：认证失败时的通知机制

## 参考资料

- [飞牛NAS网关认证文档](https://developer.fnnas.com/docs/core-concepts/gateway-authentication)
- [JWT认证最佳实践](https://jwt.io/introduction)
- [Go中间件模式](https://github.com/go-chi/chi/wiki/Middleware)

## 版本信息

- **实现日期**：2026-06-13
- **Go版本要求**：1.26.1+
- **飞牛NAS版本要求**：V1.1.3100+
