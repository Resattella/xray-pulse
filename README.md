# Xray-Pulse · 轻量级 Xray 流量监控与管控控制台

基于 FastAPI 与原生 Linux 网络栈构建的单机 Xray 流量观测与管控面板。通过直接协同 `nftables`、`iproute2 (tc / ss)` 与 Nginx 形成控制闭环，无需引入 Prometheus / Grafana 等外置采集栈或前端构建工具，覆盖 **Xray Reality（TCP 443 直连）** 与 **Cloudflare CDN WebSocket 回源** 两种接入模式，提供按“来访真实 IP”维度的实时连接追踪、双向流量统计、动态限速与即刻封禁能力。

## 特性实现

### 直连流量观测与整形（TCP 443）
- **实时连接与延迟探测**：周期性解析 `ss -tinp state established`，统计每个真实来源 IP 的 443 端口活跃连接数及 `rtt` / `minrtt` 链路延迟指标。
- **内核级精确计数与封禁**：通过独立 `nftables` 表 `inet xray_pulse` 挂载按 IP 维度的上下行字节计数规则与丢包规则（封禁覆盖 TCP 80/443 与 UDP 443）。
- **扫描噪声自动过滤**：针对公网 443 端口的高频 TLS 握手盲扫设置 `50 KB`（`51200` 字节）持久化门槛，低于阈值且无备注、限速或白名单标记的探测记录不会写入数据库。
- **无损动态带宽限速**：基于 Linux `tc` 的 `htb` 队列实现全局与单 IP 下行限速，基于 `ingress` `police` 实现上行限速；未配置任何限速策略时保留原生无损 `fq` 队列，避免中断在途流量。

### Cloudflare CDN WebSocket 识别与管控
- **回源 IP 剥离与握手鉴权**：自动剔除 Cloudflare CDN 节点网段以免误计费或误封；Nginx 在 WS 握手阶段通过 `auth_request /internal/cdn-auth` 传递 `CF-Connecting-IP` 至后端实时校验，命中黑名单即返回 `403` 拦截。
- **二进制流式计数与防回灌**：通过维护字节偏移指针流式读取 `cdn-ws.log`（兼容 `logrotate` 轮转与文件截断），配合清零/删除时间戳水位线过滤历史长连接遗留日志，防止旧流量重复入账。
- **动态限速配置下发**：根据限速策略自动生成 `cdn-rate-map.conf` 并执行平滑 `nginx -s reload`，交由 Nginx `limit_rate` 执行下行限速（CDN 模式下上行经由节点中转，上行限速仅针对直连模式生效）。

### 防误封保护与持久化安全
- **当前操作端智能识别**：针对通过代理节点或双栈多出口网络访问控制台的场景，前端通过 WebRTC STUN 探测终端公网出口候选（`X-Client-Real-IP`），后端结合代理请求头、会话 Token 绑定及在线客户端列表识别当前管理端，在界面隐藏对应“移除/封禁”按钮，并在 `/api/blacklist/add`、`/api/client/kick`、`/api/client/delete` 接口层执行硬拦截。
- **数据持久化与 GeoIP 缓存**：使用 SQLite（`data/xray_pulse.db`）存储客户端记录、别名备注、黑名单、水位线、已吊销会话与 GeoIP 归属地缓存（查询 `ip-api.com` 并做 7 天本地缓存）。
- **凭证加密与登录防爆破**：登录口令采用随机 16 字节盐 + PBKDF2-HMAC-SHA256 哈希存储，会话 Token 使用 HMAC-SHA256 签名并支持登出即时吊销；配合 Nginx `X-Real-IP` 覆写提供登录失败次数限流保护。

## 环境要求与部署

运行于 Linux 主机（需 `root` 权限执行 `nft`、`tc`、`ss` 与 `nginx -s reload`），依赖 Python 3.10+、系统工具 `nftables`、`iproute2`、`nginx` 及可选 `xray`（用于查询 `127.0.0.1:10085` StatsService 状态）。

```bash
# 安装 Python 依赖
pip install -r requirements.txt

# 放置代码至 /opt/xray-pulse 并部署 systemd 服务（默认监听 127.0.0.1:8443）
cp xray-pulse.service /etc/systemd/system/xray-pulse.service
systemctl daemon-reload
systemctl enable --now xray-pulse
```

首次初始化时，若未通过环境变量 `XP_INIT_PASS` 指定口令，后端会自动生成随机初始密码并写入 `data/initial_password.txt`（权限 `0600`），读取登录后请妥善保存。

## 环境变量说明

所有环境与端口配置均支持通过环境变量覆盖，不绑定固定服务器 IP 或内部端口：

| 变量名 | 默认值 | 说明 |
| --- | --- | --- |
| `XP_BASE_DIR` | `app.py` 所在目录 | 存放 `index.html` 与默认 `data/` 的根目录 |
| `XP_DATA_DIR` | `<XP_BASE_DIR>/data` | SQLite 数据库与 `initial_password.txt` 所在目录 |
| `XP_ADMIN_USER` | `admin` | 默认初始化管理员用户名 |
| `XP_INIT_PASS` | 留空则自动随机生成 | 首次初始化使用的管理员密码 |
| `XP_IFACE` | 自动识别默认路由网卡（回退 `eth0`） | `tc` 流量整形挂载的网卡名 |
| `XP_SERVER_IP` | 自动通过 `ip addr` 提取本机全局 IP | 逗号分隔的服务端自身 IP，避免被当成客户端入库 |
| `XP_REALITY_PORT` | `2443` | Xray Reality 本地/监听入站端口 |
| `XP_CDN_WS_PORT` | `31297` | Xray VLESS-WS 本地回源监听端口 |
| `XP_XRAY_API_SERVER` | `127.0.0.1:10085` | Xray StatsService 查询地址 |
| `XP_CDN_LOG_PATH` | `/var/log/nginx/cdn-ws.log` | Nginx 写入 CDN WebSocket 流量的日志路径 |
| `XP_CDN_RATE_MAP_PATH` | `/etc/nginx/conf.d/cdn-rate-map.conf` | 后端动态生成的 Nginx `limit_rate` 映射文件路径 |

## Nginx 反向代理参考配置

> 面板反代 `location` 中须配置 `proxy_set_header X-Real-IP $remote_addr;`，防止直连访客伪造请求头绕过 `/api/login` 失败次数限制。

在 `http` 块（例如 `/etc/nginx/conf.d/cdn-pulse.conf`）中定义日志格式并引入动态限速映射：

```nginx
log_format cdn_ws '$msec|$http_cf_connecting_ip|$bytes_sent|$upstream_bytes_sent|$request_time';
include /etc/nginx/conf.d/cdn-rate-map.conf;
```

在站点 `server` 块中配置控制台反代与 CDN WebSocket 鉴权路由：

```nginx
location = /pulse {
    return 301 https://$host/pulse/;
}

location ^~ /pulse/ {
    proxy_pass http://127.0.0.1:8443/;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header CF-Connecting-IP $http_cf_connecting_ip;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_buffering off;
    proxy_cache off;
}

location = /ws-path {
    auth_request /internal/cdn-auth;

    proxy_pass http://127.0.0.1:31297;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $connection_upgrade;
    proxy_set_header Host $host;
    proxy_read_timeout 1h;
    proxy_send_timeout 1h;
    proxy_buffering off;

    access_log /var/log/nginx/cdn-ws.log cdn_ws;
    limit_rate $cdn_rate;
}

location = /internal/cdn-auth {
    internal;
    proxy_pass http://127.0.0.1:8443/internal/cdn-auth;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Real-IP $http_cf_connecting_ip;
    proxy_set_header CF-Connecting-IP $http_cf_connecting_ip;
    proxy_set_header Host $host;
    error_page 500 502 503 504 =200 /internal/cdn-auth-pass;
}

location = /internal/cdn-auth-pass {
    internal;
    return 200;
}
```

## 文件结构

- `app.py`：单文件 FastAPI 后端，承载流量采集、`nftables` / `tc` 调度、Nginx 配置生成与鉴权接口
- `index.html`：零构建单文件控制台前端页面，内置 WebRTC STUN 终端出口探测逻辑
- `xray-pulse.service`：`systemd` 守护进程单元配置模板
- `requirements.txt`：Python 运行时依赖清单
- `LICENSE`：MIT 开源许可证

## 说明与边界

- **单机架构限定**：与宿主机的 `nftables`、`iproute2` 深度耦合，面向单机节点部署，未适配多节点集群或无特权容器环境。
- **CDN 会话隔离策略**：多个 CDN 客户端同时复用同一底层 WebSocket 端口时，为避免影响同端口其他在线会话，封禁或删除操作不强行断开整条复用隧道，而是经由 Nginx 在后续重连握手阶段拦截，并结合水位线阻断历史日志回灌。

---

*轻量级单机节点运维面板，专注低开销、零构建与原生 Linux 网络栈控制闭环。*
