# Project Structure

## 目录调整

为统一项目结构，代码与静态资源已集中放入 `src/`，并与以下目录同级：

- `documents/`
- `build/`
- `cache/`

当前根目录主要结构如下：

```text
project-root/
  src/
    go.mod
    go.sum
    main.go
    fnproxy/
    config/
    handlers/
    middleware/
    models/
    security/
    static/
    utils/
  documents/
  build/
  cache/
  certs/
  fnproxy-panel.json
  fnproxy-panel.pid
```

## 说明

- Go 入口文件已移动到 `src/main.go`。
- Go module 根目录已调整到 `src/`，`go.mod` 与 `go.sum` 均位于 `src/`。
- 后端包导入路径统一改为 `fnproxy-panel/...`。
- 前端静态资源目录已移动到 `src/static/`。
- `src/static/` 的页面资源会在构建时内嵌进可执行文件，无需单独拷贝静态文件。
- `build/` 目录预留为编译产物目录。

## 构建建议

在项目根目录执行：

```bash
go -C src build -o ../build/fnproxy-panel.exe .
```

也可以直接使用根目录脚本：

```bash
build.windows.bat
build.linux.sh
build.linux.bat
debug.bat
```
