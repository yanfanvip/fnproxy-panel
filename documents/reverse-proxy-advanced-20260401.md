# 反向代理高级配置（面板 extend_json）

与 UI 侧栏「高级配置说明」中 `reverse_proxy` 章节一致，便于检索与评审。

## preserve_host

- **true**：发往上游的 `Host` 为客户端原始 Host；HTTP 不改写 `Origin`/`Referer`；WebSocket 透传客户端 `Origin`。
- **false**：`Host` 为上游 URL 的 host（或 `host_header` 指定值）。同时将 `Origin` 设为「上游 scheme + 该 Host」；若存在 `Referer`，则把其中的 scheme、host 重写为与上游一致（路径与 query 保留）。

## host_header

仅在 **preserve_host 为 false** 时生效，覆盖发给上游的 Host；`Origin`/`Referer` 重写使用同一主机名（含端口时需写在 `host_header` 内）。

## allow_header_up

非空时：仅允许列表中的请求头名（大小写不敏感，按规范化名匹配）从**原始**客户端请求带入上游；其余客户端请求头丢弃。`Host` 始终以面板的 `preserve_host` / `host_header` / 上游地址为准，不采用客户端 `Host` 透传（请求头映射中的 `Host` 键也会被去掉）。

随后仍应用：`User-Agent` 默认、`Origin`/`Referer` 规则、`header_up` / `hide_header_up`、转发头逻辑。计算客户端 IP 与 `X-Forwarded-For` 链时仍读取**原始**请求头，故 `client_ip_header`、入站 `X-Forwarded-For` 不必列入白名单。

WebSocket：同样仅白名单透传；`Connection`、`Upgrade`、全部 `Sec-Webbsocket-*` 等永不转发（子协议仍由现有逻辑传给 `Dialer`）。

## omit_proxy_headers

为 **true** 时：删除 `X-Real-IP`、`X-Forwarded-For`、`X-Forwarded-Host`、`X-Forwarded-Proto`、`X-Forwarded-Port`、`Forwarded`，且面板不再写入上述转发头。

**优先级**：`omit_proxy_headers` 高于 `trust_proxy_headers` 与 `hide_real_ip`（后两者在「是否添加转发头」上不再起作用，结果均为无上述代理头）。

## hide_real_ip / trust_proxy_headers

`hide_real_ip` 为 true 时会清除与 `omit_proxy_headers` 相同的代理头集合，且不会由面板再写入转发头。与 `omit_proxy_headers` 同时配置时以 `omit_proxy_headers` 为准（行为上等价于不向后台暴露代理链信息）。

`trust_proxy_headers` 为 true 时不覆盖客户端已有 X-Forwarded-*；与 `omit_proxy_headers` 同时配置时以 `omit_proxy_headers` 为准。

## WebSocket

- `websocket_upstream_tls`：`http` 上游需拨 `wss` 时使用。
- `websocket_read_buffer` / `websocket_write_buffer`：客户端升级与上游拨号共用缓冲大小（字节），0 表示默认。
