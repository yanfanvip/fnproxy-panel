# 飞牛NAS网关认证集成说明

## 概述

本系统已集成飞牛NAS统一网关认证功能。当启用飞牛NAS网关认证模式时，后台管理界面将使用飞牛NAS的用户登录态进行身份验证，不再使用系统内置的管理员账号。

## 工作原理

飞牛NAS统一网关会在用户通过认证后，在转发到应用的请求中添加以下HTTP Header：

| Header | 说明 | 示例 |
|--------|------|------|
| `X-Trim-Userid` | 当前登录用户的UID | `1000` |
| `X-Trim-Isadmin` | 当前用户是否为管理员 | `true` / `false` |
| `X-Trim-Username` | 当前登录用户名 | `admin` |

应用通过这些Header识别当前用户身份和权限。

## 使用方法

### 启动参数

使用 `-oauth=fnnas` 参数启用飞牛NAS网关认证模式：

```bash
# Linux/macOS
./fnproxy -oauth=fnnas

# Windows
fnproxy.exe -oauth=fnnas
```

### 结合其他参数使用

```bash
# 指定运行目录和OAuth模式
./fnproxy -config_path=/var/run/fnproxy -oauth=fnnas

# 使用Unix Socket + 飞牛NAS认证
./fnproxy -port=sock -oauth=fnnas

# 完整示例
./fnproxy \
  -config_path=/opt/fnproxy \
  -port=8080 \
  -oauth=fnnas \
  -secure="your-secret-key"
```

## 认证流程

### 传统模式（默认）

```
用户访问 → 检查JWT Token → 验证Token有效性 → 允许/拒绝访问
```

### 飞牛NAS网关模式

```
用户访问飞牛NAS → 飞牛NAS验证登录态 → 
网关添加用户Header → 转发请求到应用 → 
应用读取Header中的用户信息 → 允许/拒绝访问
```

## 特性说明

### ✅ 支持的功能

1. **自动用户识别**：从网关Header中自动获取用户信息
2. **管理员权限判断**：根据 `X-Trim-Isadmin` 判断管理员权限
3. **会话绑定**：用户会话与飞牛NAS用户UID绑定
4. **WebSocket支持**：WebSocket连接也通过网关认证
5. **管理端安全策略**：**仅允许管理员访问管理端**，普通用户被拒绝

### ❌ 禁用的功能

当启用 `-oauth=fnnas` 时，以下功能将被禁用：

1. **传统登录接口** (`/api/login`) - 返回403错误
2. **OAuth登录页面** (`/admin-oauth`) - 返回403错误
3. **本地用户管理** - 不再使用本地用户数据库

### ⚠️ 注意事项

1. **必须通过飞牛NAS网关访问**
   - 直接访问应用端口将无法通过认证
   - 所有请求必须经过飞牛NAS统一网关

2. **管理员权限要求（重要）**
   - **管理端仅允许飞牛NAS中的管理员用户访问**
   - 普通用户访问管理端会返回 403 Forbidden 错误
   - 错误信息：“管理端仅允许管理员访问”
   - 这是为了提高安全性，防止普通用户误操作

3. **用户数据隔离**
   - 应用应根据 `X-Trim-Userid` 进行数据隔离
   - 不要信任客户端主动上报的用户ID

4. **安全性**
   - 网关负责验证用户登录态
   - 应用仍需根据自己的业务规则判断权限
   - 高风险操作需要额外校验

## 部署架构

### 推荐架构

```
用户浏览器
    ↓
飞牛NAS统一网关 (认证层)
    ↓ (添加 X-Trim-* Headers)
FnProxy 应用 (业务层)
    ↓
后端服务
```

### Nginx反向代理配置示例

如果使用Nginx作为前置代理，需要确保透传飞牛NAS的Header：

```nginx
location /fnproxy/ {
    proxy_pass http://localhost:8080/;
    
    # 透传飞牛NAS网关Header
    proxy_set_header X-Trim-Userid $http_x_trim_userid;
    proxy_set_header X-Trim-Isadmin $http_x_trim_isadmin;
    proxy_set_header X-Trim-Username $http_x_trim_username;
    
    # 其他标准Header
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

## 开发指南

### 获取当前用户信息

```go
import "fnproxy/middleware"

// 在Handler中获取用户信息
userID, isAdmin, username, err := middleware.GetFnnasUserInfo(r)
if err != nil {
    // 处理错误
}

// 或者从Context中获取Claims
claims, ok := r.Context().Value("claims").(*utils.Claims)
if ok {
    username := claims.Username
    role := claims.Role // "admin" 或 "user"
}
```

### 权限检查

```go
// 检查是否为管理员
if claims.Role != "admin" {
    WriteError(w, http.StatusForbidden, "需要管理员权限")
    return
}

// 用户数据隔离
userID, _, _, _ := middleware.GetFnnasUserInfo(r)
// 只查询当前用户的数据
data := getDataByUserID(userID)
```

## 故障排查

### 问题1：访问时提示"需要飞牛NAS网关认证"

**原因**：请求没有包含飞牛NAS网关的Header

**解决方案**：
1. 确认通过飞牛NAS网关访问应用
2. 检查网关配置是否正确
3. 查看请求中是否包含 `X-Trim-Userid`、`X-Trim-Username` 等Header

### 问题2：管理员功能无法访问

**原因**：当前用户不是飞牛NAS管理员

**解决方案**：
1. 确认飞牛NAS中该用户的角色
2. 检查 `X-Trim-Isadmin` Header的值是否为 `true`

### 问题3：WebSocket连接失败

**原因**：WebSocket也需要通过网关认证

**解决方案**：
1. 确保WebSocket连接也经过飞牛NAS网关
2. 网关会在建立连接时验证登录态并透传用户信息

## 安全建议

1. **最小权限原则**：只开放必要的路径和方法
2. **路径标准化**：对请求路径做标准化处理，防止目录穿越
3. **敏感文件保护**：不暴露配置文件、密钥、数据库等敏感文件
4. **日志审计**：记录所有管理操作，便于追溯
5. **定期更新**：保持系统和依赖库的最新版本

## 技术支持

如有问题，请参考：
- [飞牛应用开放平台文档](https://developer.fnnas.com/docs/core-concepts/gateway-authentication)
- 项目README文档
