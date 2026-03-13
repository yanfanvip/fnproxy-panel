# 服务管理

一个基于 Go 的轻量级服务管理面板，用于统一管理端口监听、反向代理、静态站点、跳转规则、证书、OAuth 访问控制、用户、SSH 终端和运行状态。

项目当前已经将前端静态资源内嵌进可执行文件，`src/` 为 Go module 根目录，运行时配置、缓存、证书和 PID 文件可统一落到 `config_path` 指定目录。

## 主要功能

- 端口监听管理：支持 `http` / `https` 监听，支持启停、热重载、状态查看。
- 服务规则管理：支持反向代理、静态文件、重定向、URL 跳转、文本输出。
- HTTPS 证书管理：支持导入证书、外部证书文件同步、ACME 自动申请与自动续期。
- 动态证书选择：HTTPS 可按域名自动匹配证书，未命中时使用内嵌默认回退证书。
- OAuth 访问控制：服务级启用认证，未登录时跳转到当前服务下的 `/OAuth`。
- 用户管理：支持新增、编辑、启停、删除用户，支持密码加密存储。
- Token 鉴权：用户可配置独立 token，请求头携带后可直接视为已登录。
- SSH / 终端管理：支持本机终端、远程 SSH、连接测试、会话恢复。
- 运行监控：提供状态、流量、连接数、访问日志等数据。
- 进程控制：支持 `status`、`stop`、`restart`，并带 PID 单实例保护。

## 目录结构

```text
fnproxy-panel/
  src/                     Go 源码与前端静态资源
    go.mod
    main.go
    fnproxy/
    config/
    handlers/
    middleware/
    models/
    security/
    static/
    utils/
  documents/               设计与变更文档
  build/                   编译输出目录
  cache/                   运行缓存目录（可选）
  build.windows.bat        Windows 构建脚本
  build.linux.bat          Windows 下交叉编译 Linux
  build.linux.sh           Linux 构建脚本
  debug.bat                本地调试脚本
```

## 环境要求

- Go `1.26.1` 或更高版本
- Windows / Linux
- 现代浏览器

## 快速开始

### 1. 开发构建

在项目根目录执行：

```bash
go -C src build -trimpath -o ../build/fnproxy-panel.exe .
```

Windows 可直接使用：

```bat
build.windows.bat
```

Linux 可使用：

```bash
sh build.linux.sh
```

或者在 Windows 下交叉编译 Linux：

```bat
build.linux.bat
```

### 2. 本地调试

```bat
debug.bat
```

`debug.bat` 会先编译调试版可执行文件，再从项目根目录下的 `debug/` 目录启动程序，便于隔离运行期配置与证书文件。

### 3. 直接运行

```bash
./build/fnproxy-panel-windows-amd64.exe
```

或在 Linux：

```bash
./build/fnproxy-panel-linux-amd64
```

## 默认登录信息

- 默认用户名：`admin`
- 默认密码：`admin`

首次部署到生产环境后，建议立即修改密码，并显式指定 `-secure` 参数。

## 启动参数

程序支持以下启动参数：

- `-secure`
  用于密码摘要、OAuth 登录加解密、SSH 密码加密等安全相关逻辑。
  未指定时默认值为 `123456`。

- `-config_path`
  指定运行时根目录。配置文件、缓存、证书、PID 文件、Socket 文件都会落到该目录下。

- `-port`
  设置管理端监听方式。
  传数字表示 TCP 端口，例如 `-port=8080`。
  传 `sock` 表示使用 Unix Socket。

- `status` 或 `-action=status`
  根据 PID 文件判断程序是否运行。

- `stop` 或 `-action=stop`
  根据 PID 文件停止当前进程。

- `restart` 或 `-action=restart`
  先停止旧进程，再启动新进程。

### 示例

使用自定义运行目录和安全参数启动：

```bash
./build/fnproxy-panel-linux-amd64 -config_path=/data/fnproxy-panel -secure="your-secret"
```

将管理后台绑定到 9090 端口：

```bash
./build/fnproxy-panel-linux-amd64 -port=9090
```

查看运行状态：

```bash
./build/fnproxy-panel-linux-amd64 status
```

停止进程：

```bash
./build/fnproxy-panel-linux-amd64 stop
```

## 运行期文件

当设置 `-config_path` 后，以下内容会统一放到该目录下：

- 主配置文件
- 监控缓存文件
- 证书目录
- PID 文件
- Unix Socket 文件

这可以避免运行时文件散落在程序目录中，便于部署和备份。

## 认证说明

### 管理后台登录

管理后台可通过用户名密码登录，登录成功后会写入 JWT Cookie。

### 服务侧 OAuth

- 服务启用 OAuth 后，未登录访问会跳转到当前服务地址下的 `/OAuth`
- 登录成功后会返回原始访问路径
- 已登录用户再次访问 `/OAuth` 时，不再展示登录页，而是继续按原始请求交给命中的服务处理

### Header Token 鉴权

用户管理中可为每个用户生成独立 token。

如果请求头中携带的 token 与某个已启用用户的 token 一致，则会直接视为该用户已登录。

支持两种写法：

```http
Auth: 32位随机token
```

```http
Authorization: Bearer 32位随机token
```

如果 `Authorization: Bearer ...` 不是用户 token，则会继续按 JWT 方式校验，因此不会影响管理后台现有登录机制。

## HTTPS 与证书

- 支持导入 PEM 证书
- 支持外部配置文件同步证书
- 支持 ACME 自动申请和自动续期
- 支持 HTTP-01 / DNS-01
- 支持腾讯云、阿里云、Cloudflare DNS
- HTTPS 监听按域名自动匹配证书
- 未匹配到业务证书时，会使用程序内嵌的默认回退证书

## SSH 与终端

- 支持本机终端
- 支持 SSH 远程连接
- 支持 SSH 连接测试
- 支持保存工作目录
- SSH 密码会在前端加密提交，并在服务端加密保存

## 前端资源

- 前端位于 `src/static/`
- 构建时通过 Go `embed` 内嵌到可执行文件
- 部署时无需额外复制静态文件目录

## 常见开发命令

运行所有包测试：

```bash
go -C src test ./...
```

运行构建：

```bash
go -C src build ./...
```

整理依赖：

```bash
go -C src mod tidy
```

## 文档

更多实现说明可参考：

- `documents/project-structure-20260312.md`
- `documents/ui-listener-fixes-20260311.md`
- `documents/certificate-management-20260312.md`
- `documents/terminal-management-20260311.md`

## 说明

- 当前项目以 `src/` 作为 Go module 根目录，`go.mod` 和 `go.sum` 位于 `src/`。
- 运行环境若未指定 `-secure`，会使用默认值 `123456`，仅适合开发调试。
- 如果已经有实例运行，再次启动会因为单实例保护而直接退出。
