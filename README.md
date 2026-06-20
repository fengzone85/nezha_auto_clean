# 哪吒漏洞 - 全自动清理脚本

针对哪吒监控面板漏洞（CVE 相关）导致的大规模服务器入侵，提供一键式自动化应急清理方案。

## 当前版本：v2.6.3

## 执行方式（推荐先下载再执行，防断网变砖）

```bash
curl -sL https://raw.githubusercontent.com/fengzone85/nezha_auto_clean/main/nezha_auto_clean.sh -o clean.sh && bash clean.sh
```

## 清理维度

| 步骤 | 清理对象 | 方法 |
|------|---------|------|
| 1 | 挖矿进程 | 名称杀 + 矿池端口检测 + 二进制特征扫描（strings） + C2 连接检测 |
| 2 | 恶意 systemd 服务 | 精确匹配 + 通配匹配 hash 后缀变体，含自动重启守护 |
| 3 | SSH 后门 | 备份公钥 → 强制开启密码登录（兼容 sshd_config.d） → 清空公钥 |
| 4 | 恶意定时任务 | 特征过滤删除（保留合法业务），含 /etc/cron.d 扫描 |
| 5 | 恶意 Docker 容器 | 流量套利容器/镜像清理 |
| 6 | 恶意文件残留 | SHA256 校验杀二进制 + 路径黑名单 |
| 7 | Docker 悬空镜像 | docker image prune |
| 8 | LD_PRELOAD 检测 | 检测并清理 /etc/ld.so.preload 及 LD_PRELOAD 环境变量劫持 |
| 9 | Shell 配置清理 | 扫描并清理 ~/.bashrc、~/.profile、/etc/profile 等 Shell 配置文件中的恶意注入 |
| 10 | 跳板代理清理 | 检测并清除攻击者部署的 frp/nps/Stowaway 等跳板代理进程及配置 |
| 11 | 最终验证 | 进程/定时任务/SSH/服务/C2 连接 五项报告 |

## IOC 覆盖

- **C2 域名**：data.sh0.cn, sh0.cn, c2tools.caoyuanke.org
- **C2 IP**：139.199.221.213, 212.83.185.19
- **恶意 SHA256**：e7260c1b6a0e932a28e36e835f15b01f2109fdce6f835b6fec74594a46fd94f0
- **系统服务**：nezha-agent-*, nazha-agent-*, pfpfybsmne, V2bX, history_check 等
- **Docker 套利**：iproyal/pawns-cli, traffmonetizer/cli_v2, lswl/vertex, honeygain, repocket 等
- **文件路径**：/tmp/.sys_*, /tmp/band.png, /opt/nvm.exe 等

## 安全机制

- SSH 公钥先备份后清空，防止锁死失联
- 强制追加 `PasswordAuthentication yes` 到 sshd_config + sshd_config.d（双路径）
- 定时任务备份到 `/tmp/crontab_bak_*`，仅过滤恶意特征保留合法业务
- 端口检测已剔除 8080/8888/9999，避免误杀 Web/面板服务
- `read -p` 强制 `< /dev/tty`，兼容 `curl | bash` 模式
- 不含远程 `curl | bash` 第三方脚本调用，杜绝供应链投毒

## 执行后

- 修改 root 密码：`passwd`
- 轮换所有 API Key（对象存储/支付/AI 等）
- 重新安装安全版哪吒监控

## 免责声明

本脚本为应急清理工具，执行前请确认已备份关键数据。作者不对因使用本脚本造成的任何损失负责。
