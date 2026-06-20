#!/bin/bash
# ====== 哪吒漏洞入侵 - 全自动清理脚本 v2.5 ======
# 用法: bash nezha_auto_clean.sh
# 或一行执行: curl -sL <url> | bash

# set -e  # 部分机器 docker 未运行会误触发退出，改用逐行 || true 保护

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
fail() { echo -e "${RED}[-]${NC} $1"; }

echo "=========================================="
echo " 哪吒后门全自动清理 v2.5"
echo "=========================================="

# ---- 1. 杀挖矿进程 ----
log "1/9 清理挖矿进程..."

# 先停挖矿相关 systemd 服务（防止 auto-restart 复活）
for miner_svc in xmrig c3pool_miner; do
    systemctl stop "$miner_svc" 2>/dev/null || true
    systemctl disable "$miner_svc" 2>/dev/null || true
done

# 方法A: 按已知名称杀
for name in xmrig xmrig-daemon stratum c3pool kdevtmpfsi kinsing sys_root_svc; do
    pkill -9 -f "$name" 2>/dev/null || true
done

# 方法B: 按端口杀——连接矿池常见端口（3333/4444/5555/14444/14433/80/443 上的 mining 协议）
MINING_PORTS="3333|4444|5555|14444|14433|8080|8888|9999"
ss -tnp 2>/dev/null | grep -E ":($MINING_PORTS)" | grep -oP 'pid=\K\d+' | sort -u | while read pid; do
    [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null || true
done

# 方法C: 搜 xmrig 二进制（按 magic bytes 或特征路径），找到后杀父进程
find /tmp /dev/shm /var/tmp /root -type f \( -name "xmrig*" -o -name "config.json" \) 2>/dev/null | while read f; do
    if strings "$f" 2>/dev/null | grep -qi "xmrig\|donate-level\|cryptonight\|randomx"; then
        warn "  发现挖矿文件: $f"
        # 找出谁在用这个文件
        lsof "$f" 2>/dev/null | awk 'NR>1{print $2}' | sort -u | while read pid; do
            kill -9 "$pid" 2>/dev/null || true
        done
        rm -rf "$f" 2>/dev/null
    fi
done

# 方法D: 检测连接已知恶意 C2 (data.sh0.cn / c2tools.caoyuanke.org) 的进程并杀
MALICIOUS_C2="data.sh0.cn|sh0.cn|c2tools.caoyuanke.org|139.199.221.213|212.83.185.19"
ss -tnp 2>/dev/null | grep -E "($MALICIOUS_C2)" | grep -oP 'pid=\K\d+' | sort -u | while read pid; do
    [ -n "$pid" ] && warn "  发现连接恶意 C2 的进程 PID=$pid" && kill -9 "$pid" 2>/dev/null || true
done

rm -rf /root/c3pool /tmp/.sys_root_svc /tmp/.sys_*_svc* /tmp/.X11-unix /tmp/.sys_lock /tmp/.sys_id /tmp/.cmd_* 2>/dev/null || true
log "  完成"

# ---- 2. 停止并删除恶意 systemd 服务 ----
log "2/9 清理恶意服务..."
MALICIOUS_SERVICES=(
    nezha-agent nazha-agent nezha-dashboard
    pfpfybsmne V2bX
    c3pool_miner xmrig
    history_check networktraffic
    BT-FirewallServices site_total
)
for svc in "${MALICIOUS_SERVICES[@]}"; do
    if systemctl is-active "$svc" &>/dev/null 2>&1; then
        systemctl stop "$svc" 2>/dev/null || true
        warn "  已停止: $svc"
    fi
    if systemctl is-enabled "$svc" &>/dev/null 2>&1; then
        systemctl disable "$svc" 2>/dev/null || true
    fi
    rm -f "/etc/systemd/system/${svc}.service" 2>/dev/null
    rm -f "/etc/systemd/system/multi-user.target.wants/${svc}.service" 2>/dev/null
    rm -f "/lib/systemd/system/${svc}.service" 2>/dev/null
done
# 通配匹配：nezha-agent-xxxxxx / nazha-agent-xxxxxx 等服务名带 hash 后缀的变体
for suffix_svc in $(systemctl list-unit-files --all 2>/dev/null | grep -iE "nezha-agent-|nazha-agent-" | awk '{print $1}' || true); do
    systemctl stop "$suffix_svc" 2>/dev/null || true
    systemctl disable "$suffix_svc" 2>/dev/null || true
    rm -f "/etc/systemd/system/${suffix_svc}" "/etc/systemd/system/multi-user.target.wants/${suffix_svc}" "/lib/systemd/system/${suffix_svc}" 2>/dev/null
    warn "  已清理: $suffix_svc"
done
systemctl daemon-reload 2>/dev/null || true
# 删除 /opt/nezha 整个目录树（含 agent config 等）
rm -rf /opt/nezha /opt/nazha 2>/dev/null || true
log "  完成"

# ---- 3. 清除 SSH 后门 ----
log "3/9 清除 SSH 后门..."
> /root/.ssh/authorized_keys 2>/dev/null || true
for dir in /home/*; do
    [ -d "$dir/.ssh" ] && > "$dir/.ssh/authorized_keys" 2>/dev/null || true
done
sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config 2>/dev/null || true
if command -v systemctl &>/dev/null; then
    systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true
else
    service sshd restart 2>/dev/null || service ssh restart 2>/dev/null || true
fi
log "  完成"

# ---- 4. 清理所有用户 crontab + 可疑系统定时任务 ----
log "4/9 清理定时任务..."
for user in $(cut -f1 -d: /etc/passwd); do
    crontab -u "$user" -r 2>/dev/null || true
done
# 清理 /etc/cron.d 中的可疑文件
if [ -d /etc/cron.d ]; then
    for f in /etc/cron.d/*; do
        [ -f "$f" ] || continue
        if grep -qiE "curl.*\|.*sh|wget.*\|.*sh|base64.*-d|/tmp/\." "$f" 2>/dev/null; then
            warn "  删除可疑文件: $f"
            rm -f "$f"
        fi
    done
fi
# 清理 /var/spool/cron
rm -rf /var/spool/cron/crontabs/* 2>/dev/null || true
rm -f /var/spool/cron/* 2>/dev/null || true
log "  完成"

# ---- 5. 清理恶意 Docker 容器 ----
log "5/9 清理恶意 Docker 容器..."
if command -v docker &>/dev/null; then
    MALICIOUS_CONTAINERS="pawns honeygain repocket tm traffmonetizer peer2profit earnapp packetstream"
    for c in $MALICIOUS_CONTAINERS; do
        docker stop "$c" 2>/dev/null || true
        docker rm "$c" 2>/dev/null || true
    done
    # 搜索其他可疑容器
    docker ps -a --format '{{.Names}}' 2>/dev/null | while read name; do
        [ -z "$name" ] && continue
        echo "$name" | grep -qiE "pawns|honeygain|repocket|traff|earn|proxy|profit|packet|iproyal" && {
            warn "  可疑容器: $name"
            docker stop "$name" 2>/dev/null || true
            docker rm "$name" 2>/dev/null || true
        } || true
    done || true
fi
log "  完成"

# ---- 6. 删除已知恶意文件 ----
log "6/9 清理恶意文件残留..."

# SHA256 匹配已知恶意 nezha-agent 二进制
KNOWN_EVIL_SHA256="e7260c1b6a0e932a28e36e835f15b01f2109fdce6f835b6fec74594a46fd94f0"
# 搜索常见路径下的 nezha-agent，校验 SHA256
for suspect in /opt/nezha/agent/nezha-agent /opt/nazha/agent/nezha-agent /usr/local/bin/nezha-agent /tmp/nezha-agent /root/nezha-agent; do
    if [ -f "$suspect" ] && command -v sha256sum &>/dev/null; then
        h=$(sha256sum "$suspect" 2>/dev/null | awk '{print $1}')
        if [ "$h" = "$KNOWN_EVIL_SHA256" ]; then
            warn "  发现恶意 nezha-agent (SHA256 匹配): $suspect"
            rm -f "$suspect"
        fi
    fi
done

rm -rf \
    /root/nezha* \
    /root/c3pool \
    /usr/local/bin/xmrig \
    /home/testnezha \
    /var/lib/sudo/lectured/testnezha \
    /tmp/band.png \
    /tmp/nvm.exe \
    /opt/band.png \
    /opt/nvm.exe \
    /tmp/.sys_*_svc* \
    /tmp/.sys_lock \
    /tmp/.sys_id \
    /tmp/.cmd_* \
    /tmp/.X11-unix \
    /tmp/.ICE-unix \
    /dev/shm/networktraffic \
    /etc/history_check \
    /usr/local/bin/history_check \
    /usr/local/bin/nazha* \
    /opt/nezha* \
    /opt/nazha* \
    2>/dev/null || true
log "  完成"

# ---- 7. 运行 Nezha-cleaner ----
log "7/9 运行 Nezha-cleaner..."
echo "y" | bash <(curl -sL https://raw.githubusercontent.com/everett7623/Nezha-cleaner/main/nezha-agent-cleaner.sh) 2>/dev/null || true
log "  完成"

# ---- 8. 清理 Docker 悬空镜像 ----
log "8/9 清理 Docker 悬空镜像..."
if command -v docker &>/dev/null; then
    docker image prune -f 2>/dev/null || true
fi
log "  完成"

# ---- 9. 最终验证 ----
log "9/9 最终验证..."

MINER_COUNT=$(ps aux | grep -iE "xmrig|miner|c3pool|kdevtmpfsi|kinsing" | grep -v grep | wc -l)
CRON_COUNT=$(crontab -l 2>/dev/null | grep -v "^#" | grep -v "^$" | wc -l || echo 0)
AUTH_COUNT=$(wc -l < /root/.ssh/authorized_keys 2>/dev/null || echo 0)
SVC_LEFT=$(systemctl list-units --all 2>/dev/null | grep -iE "nezha|nazha|pfpfybsmne|V2bX|c3pool" | wc -l || echo 0)
C2_CONN=$(ss -tnp 2>/dev/null | grep -cE "data.sh0.cn|sh0.cn|c2tools.caoyuanke.org|212.83.185.19"); C2_CONN=${C2_CONN:-0}

echo ""
echo "=========================================="
echo " 清理报告"
echo "=========================================="
echo " 挖矿进程残留 : $MINER_COUNT  (应为 0)"
echo " crontab 剩余  : $CRON_COUNT  (应为 0)"
echo " SSH 公钥数量  : $AUTH_COUNT  (应为 0)"
echo " 恶意服务残留 : $SVC_LEFT  (应为 0)"
echo " C2连接残留   : $C2_CONN  (应为 0)"
echo "=========================================="

if [ "$MINER_COUNT" -eq 0 ] && [ "$AUTH_COUNT" -eq 0 ] && [ "$SVC_LEFT" -eq 0 ] && [ "$C2_CONN" -eq 0 ]; then
    echo -e "${GREEN} 状态: 清理成功！${NC}"
else
    echo -e "${RED} 状态: 仍有残留，请手动检查${NC}"
fi

echo ""
echo " 别忘了改密码: passwd"
echo " 轮换所有 API Key（对象存储/支付/AI 等）"
echo "=========================================="
