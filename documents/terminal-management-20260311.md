# Terminal Management

## 背景

为管理后台补充可配置的终端入口，避免只能直接进入本机 Shell，无法管理多台远程主机。

## 本次改动

- 新增 `SSHConnection` 配置模型，并持久化到 `fnproxy-panel.json`。
- 新增 SSH 连接管理接口：
  - `GET /api/ssh-connections`
  - `POST /api/ssh-connections`
  - `GET /api/ssh-connections/{id}`
  - `PUT /api/ssh-connections/{id}`
  - `POST /api/ssh-connections/{id}/test`
  - `DELETE /api/ssh-connections/{id}`
- 重构 `src/handlers/terminal.go`：
  - WebSocket 终端会话改为基于连接配置启动
  - 支持本机终端与远程 SSH 两种模式
  - 支持默认工作目录、会话关闭、基础窗口尺寸同步
  - 接口返回时不再回传已保存的密码
- 更新 `src/static/index.html`：
  - 终端页面名称调整为“终端管理”
  - 入口页改为 SSH 连接卡片列表
  - 右上角提供添加 SSH 的图标按钮
  - 新增 WebSSH 详情页工具栏与状态展示
  - 引入本地静态资源版开源控件 `xterm.js` 作为远程终端渲染组件
  - WebSSH 交互改为 modal 弹窗，并增加右侧会话书签栏
- 更新 `src/static/app.js`：
  - 新增 SSH 连接列表加载、创建、编辑、删除与连接测试逻辑
  - 点击卡片创建后台托管终端会话，并以 modal 方式打开
  - WebSSH 改为基于 `xterm.js + fit addon` 渲染
  - 支持自动尺寸适配、终端焦点管理、最小化、恢复、关闭
- 更新 `src/handlers/terminal.go`：
  - 终端会话改为后台托管，前端关闭页面后仍可在保留期内恢复
  - 支持多 SSH 会话并行存在
  - 增加心跳与自动清理机制
  - modal 关闭时才真正断开后台 SSH 连接

## 验证建议

- 添加一个本机连接，确认可进入本地 Shell。
- 添加一个远程 SSH 连接，确认可用 IP、端口、用户名、密码建立会话。
- 为连接填写默认工作目录，确认进入终端后初始目录正确。
