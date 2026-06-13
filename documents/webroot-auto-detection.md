# WebRoot 自动检测功能说明

## 问题背景

当使用 Unix Socket 模式且未开启 `-oauth=fnnas` 时，如果启动脚本中 `-webroot` 参数没有正确传递，会导致：
1. 登录页面重定向 URL 错误
2. 登录成功后跳转到 404 页面

## 解决方案

### 自动检测机制

代码现在支持**从请求路径中自动提取 WebRoot**，即使启动参数中没有设置 `-webroot`。

#### 检测逻辑

```go
// 如果配置中的 WebRoot 为空，尝试从请求路径中提取
if webRoot == "" {
    reqPath := r.URL.Path
    if strings.HasPrefix(reqPath, "/app/") {
        parts := strings.SplitN(reqPath, "/", 4)
        if len(parts) >= 3 {
            webRoot = "/" + parts[1] + "/" + parts[2]
            // 例如: /app/fnproxy-panel/xxx -> /app/fnproxy-panel
        }
    }
}
```

#### 适用场景

| 访问URL | 自动检测的WebRoot | 登录页路径 | 登录后跳转 |
|---------|------------------|-----------|-----------|
| `http://192.168.0.2/app/fnproxy-panel/` | `/app/fnproxy-panel` | `/app/fnproxy-panel/admin-oauth` | `/app/fnproxy-panel/` |
| `http://192.168.0.2/myapp/` | `/myapp` | `/myapp/admin-oauth` | `/myapp/` |

---

## 调试日志

程序会输出详细的调试信息，帮助诊断问题：

### 1. 中间件重定向日志

```
[DEBUG Middleware] Config WebRoot='', RequestURI=/app/fnproxy-panel/
[DEBUG Middleware] Auto-detected WebRoot from path: /app/fnproxy-panel
[DEBUG Middleware] LoginPath='/app/fnproxy-panel/admin-oauth'
```

### 2. 登录页面渲染日志

```
[DEBUG RenderLogin] Query redirect='/app/fnproxy-panel/', Form redirect='', WebRoot=''
[DEBUG RenderLogin] Auto-detected WebRoot from path: /app/fnproxy-panel
[DEBUG RenderLogin] Final redirectTarget='/app/fnproxy-panel/'
```

### 3. 登录处理日志

```
[DEBUG Login] Form redirect='/app/fnproxy-panel/', WebRoot=''
[DEBUG Login] Auto-detected WebRoot from path: /app/fnproxy-panel
[DEBUG Login] Final redirectTarget='/app/fnproxy-panel/'
[DEBUG Login Success] Redirecting to: /app/fnproxy-panel/
```

---

## 测试步骤

### 1. 重新编译

```bash
cd /var/apps/fnproxy-panel/target
go build -o fnproxy ../../src/
```

### 2. 重启服务（不需要 -webroot 参数）

```bash
./fnproxy -action=stop

./fnproxy \
  -port=sock \
  -socketpath=/vol1/@appcenter/fnproxy-panel/fnproxy.sock \
  -config_path=/vol1/@appdata/fnproxy-panel \
  -secure="你的密钥"
```

**注意**：这次可以不加 `-webroot` 参数，系统会自动检测。

### 3. 访问并观察日志

```bash
# 访问 http://192.168.0.2/app/fnproxy-panel/
# 查看控制台输出或日志文件
tail -f /vol1/@appdata/fnproxy-panel/fnproxy.log
```

应该看到类似这样的日志：

```
[DEBUG Middleware] Config WebRoot='', RequestURI=/app/fnproxy-panel/
[DEBUG Middleware] Auto-detected WebRoot from path: /app/fnproxy-panel
[DEBUG Middleware] LoginPath='/app/fnproxy-panel/admin-oauth'
```

### 4. 登录测试

输入用户名密码登录，观察日志：

```
[DEBUG RenderLogin] Query redirect='/app/fnproxy-panel/', ...
[DEBUG Login] Form redirect='/app/fnproxy-panel/', ...
[DEBUG Login Success] Redirecting to: /app/fnproxy-panel/
```

登录后应该成功跳转到 `/app/fnproxy-panel/`，而不是 404。

---

## 推荐做法

虽然自动检测功能可以工作，但**仍然建议显式设置 `-webroot` 参数**：

```bash
WEBROOT="/app/fnproxy-panel"
CMD="${TRIM_APPDEST}/server/fnproxy-panel \
    -port=sock \
    -socketpath=${TRIM_APPDEST}/fnproxy.sock \
    -config_path=${TRIM_PKGVAR} \
    -secure=${APP_SECURE} \
    -webroot=${WEBROOT}"
```

这样可以：
- ✅ 避免依赖自动检测
- ✅ 更清晰的配置
- ✅ 减少日志输出（不需要调试）

---

## 常见问题

### Q1: 为什么我的 WebRoot 没有被检测到？

**检查点**：
1. 访问的 URL 是否以 `/app/` 开头？
2. URL 格式是否正确？例如：`/app/fnproxy-panel/`
3. 查看日志中是否有 "Auto-detected WebRoot" 的输出

### Q2: 自动检测支持哪些路径格式？

当前仅支持 `/app/xxx` 格式的路径。如果需要支持其他格式，可以修改检测逻辑：

```go
// 示例：支持 /myapp 格式
if strings.HasPrefix(reqPath, "/myapp") {
    webRoot = "/myapp"
}
```

### Q3: 如何禁用调试日志？

删除或注释掉所有 `fmt.Printf("[DEBUG ...")` 语句即可。

---

## 技术细节

### 路径解析算法

```
输入: /app/fnproxy-panel/api/status
分割: ["", "app", "fnproxy-panel", "api/status"]
提取: "/" + "app" + "/" + "fnproxy-panel" = "/app/fnproxy-panel"
```

### 优先级

1. **配置文件/启动参数** > 2. **自动检测** > 3. **默认值 `/`**

---

## 更新记录

- **2026-06-14**: 添加 WebRoot 自动检测功能
- **2026-06-14**: 增强调试日志，覆盖所有关键路径
