---
AIGC:
    Label: "1"
    ContentProducer: 001191440300708461136T1XGW3
    ProduceID: 14f21c1f9419ccbe3dfc5e2fbf7bf174_f771692c6ce511f1a99c5254007bceed
    ReservedCode1: BoBpzZ0YkRYok3mpEowJwDBucB4+ctBp+xZeYt0IhRou8RC8qhSO0AV52HF2JDCecoNjAMxy4ULUDJzBEGTy25wftbkVvDm+WNt71kA/U7ZDDvRziuz6kCYUtNnLFQP0h11nRFRAsqrii3Q+CXNtuft9AQ5+ieuuk6mYFxAItl0illyLAYXS2NyG54M=
    ContentPropagator: 001191440300708461136T1XGW3
    PropagateID: 14f21c1f9419ccbe3dfc5e2fbf7bf174_f771692c6ce511f1a99c5254007bceed
    ReservedCode2: BoBpzZ0YkRYok3mpEowJwDBucB4+ctBp+xZeYt0IhRou8RC8qhSO0AV52HF2JDCecoNjAMxy4ULUDJzBEGTy25wftbkVvDm+WNt71kA/U7ZDDvRziuz6kCYUtNnLFQP0h11nRFRAsqrii3Q+CXNtuft9AQ5+ieuuk6mYFxAItl0illyLAYXS2NyG54M=
---

# 哪吒探针漏洞攻击全记录：从入侵到清理的完整复盘

## 一、事件概述

2025-2026 年，哪吒探针（Nezha）出现严重安全漏洞，攻击者通过 Dashboard 面板漏洞批量入侵所有已连接的 Agent 节点，执行挖矿、流量套利、SSH 后门植入等恶意操作。海外 VPS（甲骨文、netcup、zap 等）几乎全灭，国内腾讯云/阿里云相对幸免。

本文基于多台被入侵服务器的实战清理经验，完整还原攻击链、提供 IOC 和清理方案。

---

## 二、攻击链还原

### 2.1 攻击入口

攻击者利用哪吒 Dashboard 漏洞，在无需 Agent Secret 爆破的情况下，通过面板直接向所有连接的 Agent 节点下发任意命令。这意味着只要你的服务器安装了哪吒 Agent 并连接到被攻破的面板，就会被控制。

### 2.2 第一阶段：初始载荷投递

攻击者下发 PowerShell / Bash 命令，从恶意服务器下载载荷：

```
212.83.185.19/band.png
```

`band.png` 名义上是图片，实为 Windows 可执行文件，保存为 `nvm.exe` 后执行。

### 2.3 第二阶段：持久化植入

攻击者部署多层持久化，确杀进程后自动复活：

| 持久化方式 | 具体表现 |
|-----------|---------|
| systemd 服务 | `nezha-agent-{hash}` / `nazha-agent-{hash}`，服务名带随机后缀 |
| crontab | `@reboot` 定时任务，系统重启后自动拉取载荷 |
| Docker watchtower | `containrrr/watchtower`，自动更新恶意容器 |
| 守护文件 | `/tmp/.sys_lock`、`/tmp/.sys_id`、`/tmp/.cmd_*` |

### 2.4 第三阶段：载荷部署

| 类型 | 内容 | 说明 |
|------|------|------|
| 挖矿 | xmrig 6.22.3 | 连接 `pool.supportxmr.com:443`，走 TLS 加密绕过端口检测 |
| 流量套利 | iproyal/pawns-cli | 带宽被转售为代理 IP |
| 流量套利 | honeygain/honeygain | 同上 |
| 流量套利 | repocket/repocket | 同上 |
| 流量套利 | traffmonetizer/cli_v2 | 同上 |
| 流量套利 | lswl/vertex | 套利 + P2P 节点 |
| 监控 | wikihostinc/looking-glass-server | 服务器状态监控 |

---

## 三、失陷指标（IOC）

### 3.1 C2 服务器

| 域名/IP | 端口 | 用途 |
|---------|------|------|
| `c2tools.caoyuanke.org` | — | C2 Dashboard |
| `data.sh0.cn` | 8008 | C2 Dashboard |
| `sh0.cn` | — | 域名注册信息关联 |
| `139.199.221.213` | — | data.sh0.cn 解析 IP |
| `212.83.185.19` | — | 初始载荷投递服务器 |

### 3.2 恶意文件特征

| 文件/路径 | 特征 |
|-----------|------|
| `/opt/nezha/agent/nezha-agent` | SHA256: `e7260c1b6a0e932a28e36e835f15b01f2109fdce6f835b6fec74594a46fd94f0` |
| `/tmp/xmrig-*/xmrig` | 挖矿程序 |
| `/tmp/band.png` / `/tmp/nvm.exe` | 初始载荷 |
| `$env:Public\nvm.exe` (Windows) | 同上 |

### 3.3 恶意进程/服务

| 名称 | 类型 |
|------|------|
| `xmrig` | 挖矿进程 |
| `c3pool_miner` | 挖矿进程 |
| `nezha-agent-*` (带 hash 后缀) | 后门 Agent |
| `nazha-agent-*` | 后门 Agent（拼写变体） |
| `pfpfybsmne` | 伪装系统服务 |
| `V2bX` | 伪装系统服务 |
| `history_check` | SSH 历史记录窃取 |
| `networktraffic` | 网络流量劫持 |

### 3.4 恶意 Docker 镜像

| 镜像 | 用途 |
|------|------|
| `iproyal/pawns-cli` | 流量套利 |
| `traffmonetizer/cli_v2` | 流量套利 |
| `lswl/vertex` / `cczc9962/vertex02` | 流量套利 |
| `honeygain/honeygain` | 流量套利 |
| `repocket/repocket` | 流量套利 |
| `containrrr/watchtower` | 自动更新（持久化辅助） |
| `wikihostinc/looking-glass-server` | 监控 |

---

## 四、自查方法

### 4.1 快速检查

```bash
# 1. 检查挖矿进程
ps aux | grep -iE "xmrig|miner|c3pool" | grep -v grep

# 2. 检查恶意服务
systemctl list-units --all | grep -iE "nezha|nazha"

# 3. 检查 SSH 后门
wc -l /root/.ssh/authorized_keys

# 4. 检查异常 Docker 容器
docker ps -a --format "table {{.Names}}\t{{.Image}}"

# 5. 检查 C2 连接
ss -tnp | grep -E "caoyuanke|sh0\.cn|212\.83\.185"

# 6. 检查 CPU 异常
top -bn1 | head -20
```

### 4.2 深度排查

```bash
# 全局搜 nezha 残留
find / -name "*nezha*" -o -name "*nazha*" 2>/dev/null

# 检查所有 crontab
for user in $(cut -f1 -d: /etc/passwd); do crontab -u "$user" -l 2>/dev/null; done

# 检查 /tmp 异常文件
ls -la /tmp/ | grep -E "\.sys_|\.cmd_|xmrig|band\.png|nvm"

# 检查可疑 systemd 服务
systemctl list-unit-files --all | grep -v -E "^(dev-|proc-|sys-|run-|snap\.|-.mount|systemd-|dbus|ssh|cron|rsyslog|network|docker|containerd|nginx|apache|mysql|php|redis)" | grep -v "^$"
```

---

## 五、清理方案

### 5.1 一键清理脚本

```bash
curl -sL https://raw.githubusercontent.com/everett7623/Nezha-cleaner/main/nezha-agent-cleaner.sh | bash
```

该脚本提供交互菜单，可选清理 Agent / Dashboard / 两者。

### 5.2 手动清理要点

**清理顺序至关重要：先停服务 → 再杀进程 → 最后删文件**，否则 systemd auto-restart 会让进程反复复活。

```bash
# 1. 停所有挖矿服务
systemctl stop xmrig c3pool_miner 2>/dev/null
systemctl disable xmrig c3pool_miner 2>/dev/null

# 2. 杀挖矿进程
pkill -9 xmrig
pkill -9 -f c3pool
pkill -9 -f kdevtmpfsi

# 3. 停带 hash 后缀的 nezha 服务
for svc in $(systemctl list-unit-files --all | grep -iE "nezha-agent-|nazha-agent-" | awk '{print $1}'); do
    systemctl stop "$svc"
    systemctl disable "$svc"
    rm -f "/etc/systemd/system/${svc}"
done

# 4. 清 SSH 后门
> /root/.ssh/authorized_keys

# 5. 清 crontab
crontab -r

# 6. 删除恶意目录
rm -rf /opt/nezha /opt/nazha /root/c3pool /tmp/xmrig-*

# 7. 删 Docker 镜像
docker rm -f pawns honeygain repocket traffmonetizer watchtower 2>/dev/null
docker rmi iproyal/pawns-cli honeygain/honeygain repocket/repocket traffmonetizer/cli_v2 containrrr/watchtower 2>/dev/null

# 8. 重载 systemd
systemctl daemon-reload

# 9. 改密码
passwd
```

### 5.3 验证清理

```bash
echo "=== 清理报告 ==="
echo "挖矿进程: $(ps aux | grep -ciE 'xmrig|miner|c3pool' | grep -v grep || echo 0)"
echo "SSH 公钥: $(wc -l < /root/.ssh/authorized_keys 2>/dev/null || echo 0)"
echo "恶意服务: $(systemctl list-units --all | grep -ciE 'nezha|nazha' || echo 0)"
```

所有指标应为 0。

---

## 六、预防建议

### 6.1 面板安全

- Dashboard 必须套 Cloudflare CDN，并开启 WAF
- Cloudflare Access / Zero Trust 加一层身份验证
- 面板端口不要使用默认值，不要直接暴露公网
- 关闭 WebSSH 功能或加白名单限制
- Agent Secret 使用强随机字符串，定期更换

### 6.2 节点安全

- 安装后立即关闭 Agent 自动更新功能
- Agent 用非 root 用户运行（最低权限原则）
- 监控异常进程：设置 CPU 使用率告警（>80% 持续 5 分钟触发）
- `/tmp` 目录挂载 `noexec` 选项
- 定期检查 crontab 和 systemd 服务列表

### 6.3 善后处理

- **立即轮换所有 API Key**：对象存储（S3/OSS/COS）、支付接口、AI 服务、邮件服务等所有凭据
- 检查云服务商控制台是否有异常登录记录
- 如果面板服务器也被入侵，所有节点考虑重装系统
- 保留入侵证据：`.bash_history`、`/var/log/` 日志，供后续溯源

---

## 七、事件时间线

| 时间 | 事件 |
|------|------|
| 2024 Q4 | 首次发现攻击者通过哪吒漏洞入侵节点 |
| 2025 年初 | 攻击手法升级：服务名加 hash 后缀、Docker 持久化 |
| 2025 年中期 | 新 C2 基础设施上线（data.sh0.cn / 212.83.185.19） |
| 2026 年 6 月 | 多台 VPS 批量清理，脚本迭代至 v2.5 |

---

## 八、鸣谢

- GitHub Issue [#1207](https://github.com/nezhahq/nezha/issues/1207) 提供早期线索
- [NodeSeek 帖子](https://www.nodeseek.com/post-781474-1) 提供受害范围参考
- [Nezha-cleaner](https://github.com/everett7623/Nezha-cleaner) 提供交互式清理工具

---

> **免责声明**：本文仅用于安全研究和防御参考。文中 IOC 信息可能随时间变化失效，请以实际情况为准。
*（内容由AI生成，仅供参考）*
