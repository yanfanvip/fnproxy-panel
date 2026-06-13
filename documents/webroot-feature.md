# Web Root 路径前缀功能说明

## 概述

Web Root 功能允许你为管理端的所有路由添加一个路径前缀，这在反向代理环境下非常有用。

## 使用场景

### 场景1：飞牛NAS应用部署

当在飞牛NAS中部署应用时，通常需要通过特定的路径访问：
- 应用URL: `http://192.168.0.2/app/fnproxy-panel`
- 登录页面: `http://192.168.0.2/app/fnproxy-panel/admin-oauth`
- API接口: `http://192.168.0.2/app/fnproxy-panel/api/status`

### 场景2：Nginx 反向代理

```nginx
location /myapp/ {
    proxy_pass http://unix:/path/to/fnproxy.sock;
}
```

访问时需要：`http://domain.com/myapp/`

---

## 使用方法

### 启动参数

使用 `-webroot` 参数指定 Web 根路径：

```bash
./fnproxy \
  -port=sock \
  -socketpath=/vol1/@appcenter/fnproxy-panel/fnproxy.sock \
  -config_path=/vol1/@appdata/fnproxy-panel \
  -secure="你的密钥" \
  -oauth=fnnas \
  -webroot=/app/fnproxy-panel
```

### 示例

#### 示例1：无前缀（默认）

```bash
./fnproxy -port=8080
```

访问地址：
- 首页: `http://localhost:8080/`
- 登录: `http://localhost:8080/admin-oauth`
- API: `http://localhost:8080/api/status`

#### 示例2：带前缀

```bash
./fnproxy -port=8080 -webroot=/myapp
```

访问地址：
- 首页: `http://localhost:8080/myapp/`
- 登录: `http://localhost:8080/myapp/admin-oauth`
- API: `http://localhost:8080/myapp/api/status`

#### 示例3：飞牛NAS环境

```bash
./fnproxy \
  -port=sock \
  -socketpath=/vol1/@appcenter/fnproxy-panel/fnproxy.sock \
  -config_path=/vol1/@appdata/fnproxy-panel \
  -secure="your-secret" \
  -oauth=fnnas \
  -webroot=/app/fnproxy-panel
```

通过飞牛NAS访问：
- `http://192.168.0.2/app/fnproxy-panel/`

---

## 特性说明

### ✅ 自动处理的功能

1. **路由前缀**：所有路由自动添加 WebRoot 前缀
   - `/` → `/app/fnproxy-panel/`
   - `/admin-oauth` → `/app/fnproxy-panel/admin-oauth`
   - `/api/*` → `/app/fnproxy-panel/api/*`
   - `/ws/*` → `/app/fnproxy-panel/ws/*`
   - `/static/*` → `/app/fnproxy-panel/static/*`

2. **重定向URL**：登录成功后的重定向会自动包含 WebRoot
   - 登录后重定向到 `/app/fnproxy-panel/`

3. **静态文件路径**：静态资源的路径也会自动调整

### ⚠️ 注意事项

1. **WebRoot 格式**：
   - 必须以 `/` 开头
   - 不要以 `/` 结尾（会自动去除）
   - 例如：`/app/fnproxy` ✅，`app/fnproxy/` ❌

2. **前端资源**：
   - 确保前端代码中的资源路径是相对的
   - 或使用正确的 basePath 配置

3. **Cookie 路径**：
   - Auth Cookie 的路径会自动设置为 WebRoot
   - 确保浏览器能正确发送 Cookie

---

## Nginx 配置示例

### 配置1：子路径反向代理

```nginx
location /fnproxy/ {
    proxy_pass http://unix:/vol1/@appcenter/fnproxy-panel/fnproxy.sock;
    
    # 传递必要的 Header
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    
    # WebSocket 支持
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
}
```

启动命令：
```bash
./fnproxy \
  -port=sock \
  -socketpath=/vol1/@appcenter/fnproxy-panel/fnproxy.sock \
  -webroot=/fnproxy
```

访问：`http://your-domain.com/fnproxy/`

### 配置2：飞牛NAS网关

飞牛NAS已经内置了网关功能，只需要：

1. 在飞牛NAS应用注册中配置应用URL
2. 启动时设置对应的 `-webroot`

---

## 故障排查

### 问题1：404 Not Found

**症状**：访问 `/app/fnproxy/` 返回 404

**原因**：
- WebRoot 配置不正确
- 路由没有正确注册

**解决**：
```bash
# 检查启动日志，确认 WebRoot 已设置
# 应该看到：Web 根路径：/app/fnproxy

# 测试基本路由
curl http://localhost/app/fnproxy/api/status
```

### 问题2：重定向循环

**症状**：浏览器不断重定向

**原因**：
- WebRoot 配置与实际访问路径不匹配
- Cookie 路径设置错误

**解决**：
1. 确认 `-webroot` 参数与 Nginx location 路径一致
2. 清除浏览器 Cookie 后重试

### 问题3：静态文件404

**症状**：页面加载了，但CSS/JS文件404

**原因**：
- 静态文件路径没有正确处理

**解决**：
- 检查浏览器控制台的网络请求
- 确认静态文件路径是否包含 WebRoot 前缀

---

## 完整示例：飞牛NAS部署

### 1. 启动脚本

```bash
#!/bin/bash
# /vol1/@appcenter/fnproxy-panel/start.sh

./fnproxy \
  -port=sock \
  -socketpath=/vol1/@appcenter/fnproxy-panel/fnproxy.sock \
  -config_path=/vol1/@appdata/fnproxy-panel \
  -secure="your-secure-key" \
  -oauth=fnnas \
  -webroot=/app/fnproxy-panel
```

### 2. 飞牛NAS应用配置

- **应用名称**: FnProxy Panel
- **应用URL**: `/app/fnproxy-panel`
- **认证方式**: 统一网关认证
- **Socket路径**: `/vol1/@appcenter/fnproxy-panel/fnproxy.sock`

### 3. 访问方式

用户通过飞牛NAS应用中心点击应用图标，自动访问：
```
http://nas-ip/app/fnproxy-panel/
```

---

## 技术实现

### 路由注册

使用 `buildPath` 辅助函数为所有路由添加前缀：

```go
buildPath := func(path string) string {
    if webRoot == "" {
        return path
    }
    return webRoot + path
}

mux.HandleFunc(buildPath("/admin-oauth"), handlers.AdminOAuthHandler)
mux.Handle(buildPath("/api/"), apiHandler)
```

### 重定向处理

在需要重定向的地方，使用 `config.GetRuntimeWebRoot()` 获取前缀：

```go
webRoot := config.GetRuntimeWebRoot()
loginPath := webRoot + "/admin-oauth"
redirectURL := fmt.Sprintf("%s?redirect=%s", loginPath, ...)
http.Redirect(w, r, redirectURL, http.StatusFound)
```

---

## 版本历史

- **2026-06-13**: 初始实现
  - 添加 `-webroot` 启动参数
  - 支持所有路由的前缀配置
  - 自动处理重定向URL
