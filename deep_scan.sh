#!/bin/bash
# ====== 生产环境深度排查脚本 v1.1 ======
# 非破坏性只读扫描，不做任何修改
# 用法: bash deep_scan.sh > scan_report.txt 2>&1

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
PASS="${GREEN}[OK]${NC}"; WARN="${YELLOW}[!]${NC}"; FAIL="${RED}[FAIL]${NC}"

echo "=============================================="
echo " 生产环境深度排查报告"
echo " 主机: $(hostname) / $(curl -s ifconfig.me 2>/dev/null || echo 'N/A')"
echo " 时间: $(date '+%Y-%m-%d %H:%M:%S')"
echo " 系统: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'"' -f2)"
echo "=============================================="

# ---- 0. LD_PRELOAD 劫持检测（最先执行，后续检测依赖此步骤） ----
echo ""; echo "=== 0. LD_PRELOAD 劫持检测 ==="

echo "--- /etc/ld.so.preload ---"
if [ -f /etc/ld.so.preload ]; then
    if [ -s /etc/ld.so.preload ]; then
        echo "$FAIL 发现全局 ld.so.preload，系统命令可能已被劫持！"
        cat /etc/ld.so.preload
    else
        echo "$PASS /etc/ld.so.preload 存在但为空（可能已被清空）"
    fi
else
    echo "$PASS 未发现 /etc/ld.so.preload"
fi

echo ""; echo "--- 进程环境变量 LD_PRELOAD ---"
LD_COUNT=0
for pid_dir in /proc/*/environ; do
    [ -f "$pid_dir" ] || continue
    if grep -q "LD_PRELOAD" "$pid_dir" 2>/dev/null; then
        pid=$(dirname "$pid_dir" | xargs basename)
        proc_name=$(ps -p "$pid" -o comm= 2>/dev/null || echo "unknown")
        echo "$FAIL PID=$pid ($proc_name) 含有 LD_PRELOAD 环境变量"
        grep -o 'LD_PRELOAD=[^[:cntrl:]]*' "$pid_dir" 2>/dev/null | head -1
        LD_COUNT=$((LD_COUNT + 1))
    fi
done 2>/dev/null
[ "$LD_COUNT" -eq 0 ] && echo "$PASS 未发现进程级 LD_PRELOAD 劫持"

# ---- 1. 进程审查 ----
echo ""; echo "=== 1. 进程审查 ==="

# CPU TOP 10
echo "--- CPU TOP 10 ---"
ps aux --sort=-%cpu | head -11

# 可疑进程：高 CPU 且命令行为空或伪造
echo ""; echo "--- 可疑进程（高CPU + 路径异常） ---"
ps aux --sort=-%cpu | awk 'NR>1 && $3>50 {print}' | while read line; do
    echo "$line" | grep -qE "\[|\]|/usr/|/lib/" || echo "$WARN $line"
done

# 无文件进程（deleted）
echo ""; echo "--- 无文件进程（deleted binary）---"
ls -l /proc/*/exe 2>/dev/null | grep deleted || echo "$PASS 未发现"

# 隐藏进程检测
echo ""; echo "--- 隐藏进程检测 ---"
PSCNT=$(ps aux | wc -l); PROCCNT=$(ls -d /proc/[0-9]* 2>/dev/null | wc -l)
[ "$PSCNT" -lt "$PROCCNT" ] && echo "$FAIL 可能存在隐藏进程: ps=$PSCNT proc=$PROCCNT" || echo "$PASS ps=$PSCNT proc=$PROCCNT 一致"

# ---- 2. 网络连接 ----
echo ""; echo "=== 2. 网络连接审查 ==="

echo "--- 监听端口 ---"
ss -tlnp 2>/dev/null

echo ""; echo "--- 异常外连 ---"
# 已知恶意目标
ss -tnp 2>/dev/null | grep -E "data\.sh0\.cn|sh0\.cn|caoyuanke|212\.83\.185|139\.199\.221|pool\.supportxmr|c3pool|moneroocean|minexmr" | while read line; do
    echo "$FAIL 恶意C2连接: $line"
done
# 检查矿池常见端口
ss -tnp 2>/dev/null | grep -E ":(3333|4444|5555|14444|14433)" | while read line; do
    echo "$WARN 矿池端口连接: $line"
done
# 所有非标准外连（剔除 Web/DNS/NTP/SSH）
echo ""; echo "--- 非常见端口外连（排除80/443/53/22）---"
ss -tnp 2>/dev/null | grep -vE ":(80|443|53|22|853|123|25|587|465|143|993|110|995|3306|5432|6379|27017) " | grep -E "ESTAB" | head -30

echo ""; echo "--- DNS 解析异常（近期查询量 Top 10）---"
if command -v journalctl &>/dev/null && journalctl -u systemd-resolved --no-pager -n 1000 2>/dev/null | grep -oP 'query:\s+\K\S+' | sort | uniq -c | sort -rn | head -10; then
    :
else
    echo "  systemd-resolved 日志不可用"
fi

echo ""; echo "--- 跳板代理工具检测（frp/chashell） ---"
FRP_PROCS=$(ps aux | grep -iE "frpc|frps|chashell" | grep -v grep)
if [ -n "$FRP_PROCS" ]; then
    echo "$FAIL 发现疑似跳板代理进程："
    echo "$FRP_PROCS"
else
    echo "$PASS 未发现"
fi

# 检查常见路径残留
for f in /tmp/frpc /tmp/frps /tmp/chashell /usr/local/bin/frpc /usr/local/bin/frps /usr/local/bin/chashell; do
    [ -f "$f" ] && echo "$FAIL 发现文件残留: $f"
done

# ---- 3. Systemd 服务 ----
echo ""; echo "=== 3. Systemd 服务审查 ==="

echo "--- 用户态异常服务 ---"
systemctl list-units --all --type=service --state=running 2>/dev/null | grep -v -E "^(●|UNIT|$)" | while read line; do
    svc=$(echo "$line" | awk '{print $1}')
    # 排除系统常见服务
    echo "$svc" | grep -qiE "^(systemd|dbus|ssh|cron|rsyslog|network|docker|containerd|nginx|apache|mysql|php|redis|fail2ban|ufw|iptables|certbot|snapd|polkit|accounts-daemon|udisks|upower|rtkit|colord|ModemManager|NetworkManager|wpa_supplicant|avahi-daemon|bluetooth|thermald|cups)" && continue
    # 标记可疑服务
    echo "$svc" | grep -qiE "nezha|nazha|pfpfybsmne|V2bX|c3pool|xmrig|history_check|networktraffic|miner|watchdog|sys_" && echo "$FAIL 恶意服务: $line" || echo "$WARN 非标准服务: $line"
done

echo ""; echo "--- 服务文件完整性 ---"
for d in /etc/systemd/system /lib/systemd/system /etc/systemd/system/multi-user.target.wants; do
    [ -d "$d" ] && find "$d" -name "*.service" -newer /etc/hostname -type f 2>/dev/null | while read f; do
        echo "$WARN 近期创建/修改: $f ($(stat -c '%y' "$f" 2>/dev/null | cut -d'.' -f1))"
    done
done

# ---- 4. 定时任务 ----
echo ""; echo "=== 4. 定时任务全量审查 ==="

for user in $(cut -f1 -d: /etc/passwd); do
    CRON=$(crontab -u "$user" -l 2>/dev/null)
    [ -z "$CRON" ] && continue
    echo "--- $user 的 crontab ---"
    echo "$CRON" | while read line; do
        [ -z "$line" ] && continue
        echo "$line" | grep -q "^#" && { echo "  (注释) $line"; continue; }
        echo "$line" | grep -qiE "curl.*\|.*sh|wget.*\|.*sh|base64.*-d|/tmp/\.sys_|c3pool|xmrig|band\.png|nvm\.exe|\.sh0\.cn|caoyuanke" && \
            echo "$FAIL $user: $line" || echo "  $line"
    done
done

echo ""; echo "--- /etc/cron.d 审查 ---"
[ -d /etc/cron.d ] && for f in /etc/cron.d/*; do
    [ -f "$f" ] || continue
    echo "  [$f]"
    grep -v "^#" "$f" 2>/dev/null | grep -v "^$" | while read line; do
        echo "$line" | grep -qiE "curl.*\|.*sh|wget.*\|.*sh|base64|/tmp/\.|\.sys_|c3pool|xmrig" && echo "$FAIL   $line" || echo "    $line"
    done
done

echo ""; echo "--- anacron / at 队列 ---"
atq 2>/dev/null || echo "  无 at 队列或 at 未安装"

# ---- 5. SSH 审查 ----
echo ""; echo "=== 5. SSH 安全审查 ==="

echo "--- /root/.ssh/authorized_keys ---"
if [ -f /root/.ssh/authorized_keys ] && [ -s /root/.ssh/authorized_keys ]; then
    KEYCOUNT=$(wc -l < /root/.ssh/authorized_keys)
    echo "  公钥数量: $KEYCOUNT"
    cat -n /root/.ssh/authorized_keys 2>/dev/null
else
    echo "$PASS 无 root 公钥（仅密码登录或文件为空）"
fi

echo ""; echo "--- 其他用户 authorized_keys ---"
for dir in /home/*; do
    [ -d "$dir/.ssh" ] && [ -f "$dir/.ssh/authorized_keys" ] && [ -s "$dir/.ssh/authorized_keys" ] && \
        echo "$WARN $(basename $dir): $(wc -l < $dir/.ssh/authorized_keys) 个公钥"
done

echo ""; echo "--- SSH 配置审查 ---"
grep -E "^(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|Port|AllowUsers|AllowGroups)" /etc/ssh/sshd_config 2>/dev/null
for f in /etc/ssh/sshd_config.d/*.conf; do
    [ -f "$f" ] && echo "  [$f]" && grep -E "^(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|Port)" "$f" 2>/dev/null
done

# ---- 5.5. Shell 配置文件后门检测（复活机制） ----
echo ""; echo "=== 5.5. Shell 配置文件后门 ==="
SHELL_RC_PATTERN="curl.*\|.*sh|wget.*\|.*sh|base64.*-d|/tmp/\.sys_|c3pool|xmrig|band\.png|nvm\.exe|frpc|frps|chashell"

for rc in /root/.bashrc /root/.profile /root/.bash_profile /etc/profile; do
    [ -f "$rc" ] || continue
    if grep -qiE "$SHELL_RC_PATTERN" "$rc" 2>/dev/null; then
        echo "$FAIL $rc 含有可疑注入！"
        grep -inE "$SHELL_RC_PATTERN" "$rc" 2>/dev/null | head -5
    else
        echo "$PASS $rc"
    fi
done

for homedir in /home/*; do
    for rc in .bashrc .profile .bash_profile; do
        [ -f "$homedir/$rc" ] || continue
        if grep -qiE "$SHELL_RC_PATTERN" "$homedir/$rc" 2>/dev/null; then
            echo "$FAIL $homedir/$rc 含有可疑注入！"
            grep -inE "$SHELL_RC_PATTERN" "$homedir/$rc" 2>/dev/null | head -5
        fi
    done
done

# ---- 6. 用户与权限 ----
echo ""; echo "=== 6. 用户与权限审查 ==="

echo "--- 近期新增用户（passwd 7天内修改）---"
find /etc/passwd -mtime -7 2>/dev/null && echo "$WARN /etc/passwd 近期被修改" || echo "$PASS /etc/passwd 近期无变更"

echo ""; echo "--- 可登录用户 ---"
grep -vE "/(nologin|false)$" /etc/passwd | cut -d: -f1

echo ""; echo "--- sudoers 审查 ---"
grep -v "^#" /etc/sudoers 2>/dev/null | grep -v "^$" | grep -v "^Defaults"
for f in /etc/sudoers.d/*; do
    [ -f "$f" ] && echo "  [$f]" && grep -v "^#" "$f" 2>/dev/null | grep -v "^$"
done

echo ""; echo "--- setuid/setgid 文件 ---"
find / -path /proc -prune -o -path /sys -prune -o -path /snap -prune -o -type f \( -perm -4000 -o -perm -2000 \) -newer /etc/hostname 2>/dev/null | head -20

# ---- 7. 文件系统 ----
echo ""; echo "=== 7. 文件系统审查 ==="

echo "--- /tmp 可疑文件 ---"
ls -la /tmp/ | grep -E "\.sys_|\.cmd_|\.lock|\.id|xmrig|band\.png|nvm\.exe|\.X11|\.ICE" 2>/dev/null || echo "$PASS 未发现"

echo ""; echo "--- /tmp 可执行文件 ---"
find /tmp -type f -perm /111 2>/dev/null | head -20

echo ""; echo "--- /dev/shm 内容 ---"
ls -la /dev/shm/ 2>/dev/null | grep -v "^total" || echo "  空"

echo ""; echo "--- 可疑隐藏文件 ---"
find /tmp /var/tmp /dev/shm -name ".*" -type f -perm /111 2>/dev/null | head -20

echo ""; echo "--- /opt 目录 ---"
ls -la /opt/ 2>/dev/null

echo ""; echo "--- 近期修改的可执行文件（7天内）---"
find /tmp /dev/shm /var/tmp /root /home -type f -perm /111 -mtime -7 2>/dev/null | head -20

echo ""; echo "--- nezha 残留 ---"
find / -path /proc -prune -o -path /sys -prune -o -path /snap -prune -o \( -name "*nezha*" -o -name "*nazha*" \) 2>/dev/null | head -30

# ---- 8. Docker 审查 ----
echo ""; echo "=== 8. Docker 审查 ==="

if command -v docker &>/dev/null; then
    echo "--- 运行中的容器 ---"
    docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null

    echo ""; echo "--- 所有容器 ---"
    docker ps -a --format "table {{.Names}}\t{{.Image}}\t{{.Status}}" 2>/dev/null

    echo ""; echo "--- 可疑镜像（流量套利）---"
    docker images --format "{{.Repository}}:{{.Tag}}" 2>/dev/null | grep -iE "pawns|honeygain|repocket|traff|earn|iproyal|vertex|lswl" || echo "$PASS 未发现恶意镜像"

    echo ""; echo "--- 特权容器 ---"
    docker ps -q 2>/dev/null | while read cid; do
        docker inspect "$cid" 2>/dev/null | grep -q '"Privileged": true' && echo "$FAIL 特权容器: $(docker inspect --format '{{.Name}}' "$cid")"
    done
else
    echo "Docker 未安装"
fi

# ---- 9. 内核模块 ----
echo ""; echo "=== 9. 内核模块审查 ==="

echo "--- 已加载内核模块 ---"
lsmod 2>/dev/null | grep -v "^Module" | while read mod rest; do
    echo "$mod" | grep -qiE "rootkit|suterusu|diamorphine|adore|knark|kbeast|phalanx|Rkit" && echo "$FAIL 可疑内核模块: $mod" || true
done

# 检查 rootkit 常见特征
echo ""; echo "--- Rootkit 快速检测 ---"
[ -f /proc/modules ] && grep -qiE "rootkit|suterusu|diamorphine|adore" /proc/modules && echo "$FAIL /proc/modules 异常" || echo "$PASS /proc/modules"
[ -d /proc/vmallocinfo ] && echo "  proc/vmallocinfo: 存在" || echo "  proc/vmallocinfo: 正常"
ls /proc/1/ 2>/dev/null | head -5 >/dev/null && echo "$PASS 可访问 PID 1" || echo "$FAIL 无法访问 PID 1"
grep -q "rtld" /proc/1/maps 2>/dev/null && echo "$WARN PID 1 maps 含 rtld（可能被注入）" || echo "$PASS PID 1 maps 正常"

# ---- 10. 日志审查 ----
echo ""; echo "=== 10. 日志审查 ==="

echo "--- 近期 SSH 登录（成功/失败 Top 10）---"
if [ -f /var/log/auth.log ]; then
    grep "Accepted" /var/log/auth.log 2>/dev/null | tail -10
elif [ -f /var/log/secure ]; then
    grep "Accepted" /var/log/secure 2>/dev/null | tail -10
else
    journalctl -u sshd --no-pager -n 30 2>/dev/null | grep "Accepted" | tail -10
fi

echo ""; echo "--- sudo 使用记录（最近 20 条）---"
grep "sudo" /var/log/auth.log 2>/dev/null | tail -20 || grep "sudo" /var/log/secure 2>/dev/null | tail -20

echo ""; echo "--- .bash_history 可疑命令 ---"
for hf in /root/.bash_history /home/*/.bash_history; do
    [ -f "$hf" ] || continue
    SUSP=$(grep -iE "curl.*\|.*sh|wget.*\|.*sh|base64.*-d|nc -e|bash -i >&|python.*pty|/tmp/band\.png|/tmp/nvm\.exe" "$hf" 2>/dev/null)
    [ -n "$SUSP" ] && echo "$FAIL $hf: $SUSP"
done

# ---- 11. 包完整性（如果是 Debian/Ubuntu） ----
echo ""; echo "=== 11. 包完整性 ==="
if command -v debsums &>/dev/null; then
    echo "--- 关键包校验（debsums）---"
    debsums -c 2>/dev/null | head -30 || echo "$PASS 全部通过"
elif command -v rpm &>/dev/null; then
    echo "--- 关键包校验（rpm -Va）---"
    rpm -Va 2>/dev/null | grep -v "^\.\{8\}" | head -30 || echo "$PASS 全部通过"
else
    echo "  无法校验（debsums/rpm 不可用）"
fi

# ---- 12. 资源异常 ----
echo ""; echo "=== 12. 资源占用 ==="

echo "--- 磁盘使用 ---"
df -h | grep -vE "tmpfs|devtmpfs|overlay"

echo ""; echo "--- 内存使用 ---"
free -h

echo ""; echo "--- 网络流量异常（网卡 30 秒采样）---"
if command -v ifstat &>/dev/null; then
    ifstat -i eth0 1 3 2>/dev/null || true
elif command -v sar &>/dev/null; then
    sar -n DEV 1 3 2>/dev/null | head -20 || true
else
    DEV=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'dev \K\S+')
    [ -n "$DEV" ] && echo "  主网卡: $DEV  rx: $(cat /sys/class/net/$DEV/statistics/rx_bytes 2>/dev/null)  tx: $(cat /sys/class/net/$DEV/statistics/tx_bytes 2>/dev/null)"
fi

echo ""; echo "=============================================="
echo " 扫描完成"
echo "=============================================="
