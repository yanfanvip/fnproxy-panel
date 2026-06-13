# 飞牛NAS网关认证 - 快速开始

## 5分钟快速上手

### 步骤1：编译程序

```bash
cd d:\workspaces\飞牛代理\src
go build -o ..\fnproxy.exe .
```

### 步骤2：选择认证模式

#### 模式A：传统认证（默认）

适合独立部署，使用本地用户管理：

```bash
.\fnproxy.exe -port=8080
```

访问：http://localhost:8080  
账号：admin / admin

#### 模式B：飞牛NAS网关认证

适合集成到飞牛NAS系统：

```bash
.\fnproxy.exe -port=8080 -oauth=fnnas
```

**重要**：必须通过飞牛NAS网关访问，不能直接访问8080端口。

### 步骤3：配置飞牛NAS网关

在飞牛NAS的应用注册中配置：

1. **应用URL**：指向FnProxy的地址
2. **认证方式**：启用统一网关认证
3. **权限设置**：**仅配置管理员用户**（重要！）
   - 普通用户访问管理端会被拒绝
   - 确保只有授权的管理员可以访问

### 步骤4：测试访问

#### 传统模式测试

```bash
# 1. 登录获取Token
curl -X POST http://localhost:8080/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'

# 2. 使用Token访问API
curl http://localhost:8080/api/me \
  -H "Authorization: Bearer YOUR_TOKEN"
```

#### 飞牛NAS模式测试

```bash
# 模拟飞牛NAS网关的请求
curl http://localhost:8080/api/me \
  -H "X-Trim-Userid: 1000" \
  -H "X-Trim-Username: testuser" \
  -H "X-Trim-Isadmin: true"
```

预期返回：
```json
{
  "success": true,
  "data": {
    "username": "testuser",
    "email": "",
    "enabled": true,
    "role": "admin"
  }
}
```

## 常见问题

### Q1: 什么时候使用飞牛NAS认证？

**答**：当你的应用需要：
- 集成到飞牛NAS生态系统
- 使用飞牛NAS的统一用户管理
- 实现单点登录（SSO）
- 遵循飞牛NAS的安全规范

### Q2: 为什么普通用户无法访问管理端？

**答**：这是**安全策略设计**：
- 管理端涉及系统配置和敏感操作
- 仅允许飞牛NAS管理员访问，防止误操作
- 普通用户访问会返回 `403 Forbidden` 错误
- 如需给普通用户提供只读功能，需要单独开发接口

### Q3: 两种模式可以切换吗？

**答**：可以。只需修改启动参数并重启服务：
- 切换到传统模式：去掉 `-oauth=fnnas` 参数
- 切换到飞牛NAS模式：添加 `-oauth=fnnas` 参数

### Q4: 飞牛NAS模式下还能创建本地用户吗？

**答**：可以创建，但不会用于认证。用户管理功能仍然可用，仅用于记录和管理。

### Q5: 如何判断当前使用的是哪种模式？

**答**：查看启动日志，会显示：
```
OAuth 认证模式：fnnas
使用飞牛NAS网关认证模式
```

或者没有显示则表示使用传统模式。

### Q6: WebSocket终端在飞牛NAS模式下能用吗？

**答**：可以。WebSocket连接也会经过网关认证，网关会透传用户信息。

## 故障排除

### 问题：提示"需要飞牛NAS网关认证"

**原因**：请求缺少必要的Header

**解决**：
1. 确认通过飞牛NAS网关访问
2. 检查网关是否正确配置
3. 验证请求中包含以下Header：
   - `X-Trim-Userid`
   - `X-Trim-Username`
   - `X-Trim-Isadmin`

### 问题：管理员功能无法访问

**原因**：当前用户不是管理员

**解决**：
1. 确认飞牛NAS中该用户的角色为管理员
2. 检查 `X-Trim-Isadmin` Header的值是否为 `true`
3. **注意**：在飞牛NAS模式下，管理端仅允许管理员访问，普通用户会被拒绝

### 问题：登录后立即被踢出

**原因**：可能是Session冲突或Token过期

**解决**：
1. 清除浏览器缓存和Cookie
2. 重新登录
3. 检查系统时间是否同步

## 下一步

- 📖 阅读完整文档：[fnnas-oauth-integration.md](./fnnas-oauth-integration.md)
- 🔍 查看实现细节：[fnnas-oauth-implementation-summary.md](./fnnas-oauth-implementation-summary.md)
- 💻 查看源代码：`src/middleware/fnnas_auth.go`

## 技术支持

遇到问题？
1. 查看日志输出
2. 检查飞牛NAS网关配置
3. 参考官方文档：https://developer.fnnas.com
