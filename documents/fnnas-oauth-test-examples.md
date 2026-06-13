# 飞牛NAS管理员权限测试示例

## 测试场景

### 场景1：管理员用户访问（应该成功）

```bash
# 模拟管理员用户的请求
curl http://localhost:8080/api/me \
  -H "X-Trim-Userid: 1000" \
  -H "X-Trim-Username: admin" \
  -H "X-Trim-Isadmin: true"
```

**预期结果**：
```json
{
  "success": true,
  "data": {
    "username": "admin",
    "email": "",
    "enabled": true,
    "role": "admin"
  }
}
```

---

### 场景2：普通用户访问管理端（应该被拒绝）

```bash
# 模拟普通用户的请求
curl http://localhost:8080/api/me \
  -H "X-Trim-Userid: 1001" \
  -H "X-Trim-Username: user1" \
  -H "X-Trim-Isadmin: false"
```

**预期结果**：
```json
{
  "success": false,
  "error": "管理端仅允许管理员访问"
}
```

HTTP状态码：`403 Forbidden`

---

### 场景3：缺少Header（应该被拒绝）

```bash
# 没有提供必要的Header
curl http://localhost:8080/api/me
```

**预期结果**：
```json
{
  "success": false,
  "error": "需要飞牛NAS网关认证"
}
```

HTTP状态码：`401 Unauthorized`

---

### 场景4：访问公开接口（应该成功）

```bash
# GeoIP是公开接口，不需要认证
curl http://localhost:8080/api/geoip?ip=8.8.8.8
```

**预期结果**：返回GeoIP信息（无论是否有认证Header）

---

### 场景5：WebSocket连接（管理员）

```javascript
// 管理员用户的WebSocket连接
const ws = new WebSocket('ws://localhost:8080/ws/terminal?session_id=xxx');

// 在建立连接时，浏览器会自动携带Cookie或通过网关透传Header
// 如果是管理员，连接成功
// 如果是普通用户，连接会被拒绝
```

---

## 使用Postman测试

### 设置Headers

1. **管理员测试**：
   ```
   X-Trim-Userid: 1000
   X-Trim-Username: admin
   X-Trim-Isadmin: true
   ```

2. **普通用户测试**：
   ```
   X-Trim-Userid: 1001
   X-Trim-Username: user1
   X-Trim-Isadmin: false
   ```

### 测试API端点

- `GET http://localhost:8080/api/me` - 获取当前用户
- `GET http://localhost:8080/api/listeners` - 获取监听器列表
- `POST http://localhost:8080/api/listeners` - 创建监听器（仅管理员）
- `GET http://localhost:8080/api/users` - 获取用户列表（仅管理员）

---

## 使用Python测试脚本

```python
import requests

BASE_URL = "http://localhost:8080"

def test_admin_access():
    """测试管理员访问"""
    headers = {
        "X-Trim-Userid": "1000",
        "X-Trim-Username": "admin",
        "X-Trim-Isadmin": "true"
    }
    
    response = requests.get(f"{BASE_URL}/api/me", headers=headers)
    print(f"管理员访问状态码: {response.status_code}")
    print(f"响应: {response.json()}")
    assert response.status_code == 200
    assert response.json()["data"]["role"] == "admin"

def test_user_access_denied():
    """测试普通用户被拒绝"""
    headers = {
        "X-Trim-Userid": "1001",
        "X-Trim-Username": "user1",
        "X-Trim-Isadmin": "false"
    }
    
    response = requests.get(f"{BASE_URL}/api/me", headers=headers)
    print(f"普通用户访问状态码: {response.status_code}")
    print(f"响应: {response.json()}")
    assert response.status_code == 403
    assert "仅允许管理员" in response.json()["error"]

def test_no_auth():
    """测试无认证"""
    response = requests.get(f"{BASE_URL}/api/me")
    print(f"无认证访问状态码: {response.status_code}")
    print(f"响应: {response.json()}")
    assert response.status_code == 401

if __name__ == "__main__":
    print("=== 测试管理员访问 ===")
    test_admin_access()
    
    print("\n=== 测试普通用户被拒绝 ===")
    test_user_access_denied()
    
    print("\n=== 测试无认证 ===")
    test_no_auth()
    
    print("\n✅ 所有测试通过！")
```

运行测试：
```bash
python test_fnnas_auth.py
```

---

## 使用curl批量测试

创建测试脚本 `test-auth.sh`：

```bash
#!/bin/bash

BASE_URL="http://localhost:8080"

echo "=== 测试1: 管理员访问 ==="
curl -s -w "\nHTTP状态码: %{http_code}\n" \
  -H "X-Trim-Userid: 1000" \
  -H "X-Trim-Username: admin" \
  -H "X-Trim-Isadmin: true" \
  $BASE_URL/api/me

echo ""
echo "=== 测试2: 普通用户访问（应被拒绝）==="
curl -s -w "\nHTTP状态码: %{http_code}\n" \
  -H "X-Trim-Userid: 1001" \
  -H "X-Trim-Username: user1" \
  -H "X-Trim-Isadmin: false" \
  $BASE_URL/api/me

echo ""
echo "=== 测试3: 无认证访问（应被拒绝）==="
curl -s -w "\nHTTP状态码: %{http_code}\n" \
  $BASE_URL/api/me

echo ""
echo "=== 测试4: 公开接口（应成功）==="
curl -s -w "\nHTTP状态码: %{http_code}\n" \
  $BASE_URL/api/geoip?ip=8.8.8.8
```

运行测试：
```bash
chmod +x test-auth.sh
./test-auth.sh
```

---

## 预期测试结果总结

| 测试场景 | Header配置 | 预期状态码 | 说明 |
|---------|-----------|----------|------|
| 管理员访问 | `X-Trim-Isadmin: true` | 200 | ✅ 允许访问 |
| 普通用户访问 | `X-Trim-Isadmin: false` | 403 | ❌ 拒绝访问 |
| 无认证 | 无Header | 401 | ❌ 需要认证 |
| 公开接口 | 任意 | 200 | ✅ 无需认证 |

---

## 故障排查

### 问题：普通用户仍然可以访问

**检查**：
1. 确认启动了 `-oauth=fnnas` 参数
2. 检查日志中是否显示"使用飞牛NAS网关认证模式"
3. 确认 `X-Trim-Isadmin` Header的值确实是 `"false"`（字符串）

### 问题：管理员也被拒绝

**检查**：
1. 确认 `X-Trim-Isadmin` Header的值是 `"true"`（字符串，区分大小写）
2. 检查是否有空格或其他字符
3. 查看应用日志中的错误信息

### 问题：所有请求都被拒绝

**检查**：
1. 确认提供了所有必需的Header：
   - `X-Trim-Userid`
   - `X-Trim-Username`
   - `X-Trim-Isadmin`
2. 确认Header名称拼写正确（区分大小写）
3. 检查是否通过了飞牛NAS网关

---

## 安全建议

1. **生产环境**：确保应用只能通过飞牛NAS网关访问
2. **防火墙规则**：阻止直接访问应用端口
3. **日志监控**：记录所有403拒绝访问的尝试
4. **定期审计**：检查飞牛NAS中的管理员用户列表
