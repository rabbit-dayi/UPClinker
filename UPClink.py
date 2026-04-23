# coding=utf-8
import os
import sys
import urllib.request
import urllib.parse
import urllib.error
import time
import socket
import struct
import base64
import threading
import subprocess
import re
import json

class UPCPortal:
    def __init__(self):
        self.domains = ['wlan.upc.edu.cn', 'lan.upc.edu.cn']
        self.dns_servers = ['121.251.251.250', '121.251.251.251']
        self.login_path = '/eportal/InterFace.do?method=login'
        self.config_file = os.path.expanduser('~/.upc') 
        
        self.ref_url = ''
        self.active_domain = 'wlan.upc.edu.cn'
        self.portal_ip = ''
        self.portal_scheme = 'http'
        self.portal_netloc = ''
        self.portal_origin = ''
        self.portal_connect_netloc = ''
        self.external_probe_host = 'www.baidu.com'
        self.external_probe_ip = ''
        self.last_status = None 
        self.last_link_status = None
        self.last_network_snapshot = {}
        self.dns_timeout = 0.5
        self.http_probe_timeout = 1.2
        self.login_timeout = 4
        self.login_retry_at = 0.0
        self.login_retry_reason = ""
        self.login_retry_notice_at = 0.0
        self.login_retry_backoff = 10
        self.login_retry_backoff_max = 120
        self.login_permanent_retry_delay = 300
        
        # --- 状态管理 ---
        self.is_heartbeat_printing = False
        self.in_config_mode = False 
        self.current_uid = ""
        self.current_pwd = ""
        self.current_srv = ""
        
        self.req_header = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Connection': 'Keep-Alive',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        }
        
        # 拦截器：坚决斩断所有自动 302 跳转，防止死循环
        class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None 

        self.opener = urllib.request.build_opener(NoRedirectHandler())

    def log(self, message, level="+", inline=False):
        curr_time = time.strftime("%H:%M:%S", time.localtime())
        colors = {"+": "\033[32m", "-": "\033[31m", "*": "\033[36m", "!": "\033[33m", "R": "\033[0m"}
        
        if self.is_heartbeat_printing and not inline:
            print("") 
            self.is_heartbeat_printing = False
            
        formatted_msg = f"[{curr_time}] {colors.get(level, '')}[{level}]{colors['R']} {message}"
        
        if inline:
            sys.stdout.write(f"\r\033[K{formatted_msg}") 
            sys.stdout.flush()
            self.is_heartbeat_printing = True
        else:
            print(formatted_msg)

    def load_config(self):
        if not os.path.exists(self.config_file):
            return False
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            if not lines: return False
            parts = lines[0].strip().split()
            self.current_uid = parts[0]
            self.current_pwd = base64.b64decode(parts[1]).decode()
            self.current_srv = parts[2] if len(parts) > 2 else ""
            return True
        except Exception:
            return False

    def reset_login_retry_state(self):
        self.login_retry_at = 0.0
        self.login_retry_reason = ""
        self.login_retry_notice_at = 0.0
        self.login_retry_backoff = 10

    def interactive_setup(self):
        self.in_config_mode = True
        time.sleep(0.2)  
        
        sys.stdout.write("\r\033[K")
        print("\033[36m" + "-"*45 + "\033[0m")
        self.log("进入配置修改模式 (按 Ctrl+C 可取消)", "!")
        try:
            uid = input(" -> 账号 (学号): ").strip()
            if not uid: 
                self.log("账号为空，已取消修改。", "-")
                return
            pwd = input(" -> 密码: ").strip()
            print(" -> 运营商 [1:校园网(默认)  2:电信  3:联通  4:移动]")
            srv_choice = input(" -> 选择: ").strip()
            
            srv_map = {"2": "telecom", "3": "unicom", "4": "cmcc"}
            srv = srv_map.get(srv_choice, "")

            pwd_enc = base64.b64encode(pwd.encode()).decode() 
            line = f"{uid} {pwd_enc} {srv}".strip()
            
            with open(self.config_file, 'w', encoding='utf-8') as f:
                f.write(line + "\n")
            
            self.load_config() 
            self.reset_login_retry_state()
            self.log(f"账号 [{self.current_uid}] 已加密写入配置！", "+")
            
        except KeyboardInterrupt:
            print("\n")
            self.log("用户取消了配置修改，恢复监控。", "*")
        finally:
            print("\033[36m" + "-"*45 + "\033[0m")
            self.in_config_mode = False 

    def query_dns(self, domain, dns_ip):
        s = None
        try:
            req = struct.pack('!HHHHHH', 0x0001, 0x0100, 1, 0, 0, 0)
            for part in domain.split('.'):
                req += struct.pack('!B', len(part)) + part.encode()
            req += struct.pack('!BHH', 0, 1, 1) 
            
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(self.dns_timeout) 
            s.sendto(req, (dns_ip, 53))
            res, _ = s.recvfrom(1024)
            
            idx = 12
            while res[idx] != 0: idx += res[idx] + 1
            idx += 15 
            if struct.unpack('!H', res[idx:idx+2])[0] == 4: 
                return socket.inet_ntoa(res[idx+2:idx+6])
        except Exception:
            pass
        finally:
            if s:
                s.close()
        return None

    def _parse_portal_from_ref(self):
        if not self.ref_url:
            return

        parsed = urllib.parse.urlparse(self.ref_url)
        self.portal_scheme = parsed.scheme or 'http'
        self.portal_netloc = parsed.netloc

        host = parsed.hostname or parsed.netloc.split(':')[0]
        port = parsed.port

        if self.portal_netloc:
            self.portal_origin = f"{self.portal_scheme}://{self.portal_netloc}"
        else:
            self.portal_origin = ''

        self.active_domain = self.portal_netloc or host or self.active_domain

        if host and any(c.isalpha() for c in host):
            ip = self.resolve_domain(host)
            connect_host = ip if ip else host
        else:
            connect_host = host

        self.portal_ip = connect_host or ''
        if connect_host:
            self.portal_connect_netloc = f"{connect_host}:{port}" if port else connect_host
        else:
            self.portal_connect_netloc = ''

    def _get_portal_connect_origin(self):
        if self.portal_connect_netloc:
            return f"{self.portal_scheme}://{self.portal_connect_netloc}"
        if self.portal_origin:
            return self.portal_origin
        if self.portal_ip:
            return f"http://{self.portal_ip}"
        return ""

    def _get_origin_header(self):
        return self.portal_origin or self._get_portal_connect_origin()

    def _get_portal_query_string(self):
        if not self.ref_url:
            return ""
        parsed = urllib.parse.urlsplit(self.ref_url)
        return parsed.query or ""

    def resolve_domain(self, domain):
        for dns in self.dns_servers:
            ip = self.query_dns(domain, dns)
            if ip:
                return ip
        return None

    def _read_text_file(self, path):
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read().strip()
        except Exception:
            return ""

    def _normalize_linux_interface_state(self, operstate, carrier):
        if carrier == '1' or (carrier == "" and operstate == 'up'):
            return 'connected'
        if operstate:
            return operstate
        return 'unknown'

    def _get_linux_network_snapshot(self):
        base_dir = '/sys/class/net'
        if not os.path.isdir(base_dir):
            return None

        snapshot = {}
        for iface in sorted(os.listdir(base_dir)):
            if iface == 'lo':
                continue

            iface_dir = os.path.join(base_dir, iface)
            iface_type = self._read_text_file(os.path.join(iface_dir, 'type'))
            if iface_type in {'772', '65534'}:
                continue

            operstate = self._read_text_file(os.path.join(iface_dir, 'operstate')).lower()
            carrier = self._read_text_file(os.path.join(iface_dir, 'carrier'))
            snapshot[iface] = self._normalize_linux_interface_state(operstate, carrier)

        return snapshot

    def _normalize_windows_interface_state(self, admin_state, state):
        admin_state = admin_state.strip().lower()
        state = state.strip().lower()

        if admin_state in {'disabled', '已禁用'}:
            return 'disabled'
        if state in {'connected', '已连接'}:
            return 'connected'
        if state in {'disconnected', '已断开连接', '断开连接', '未连接'}:
            return 'disconnected'
        if state in {'connecting', '正在连接'}:
            return 'connecting'
        return state or 'unknown'

    def _get_windows_network_snapshot(self):
        try:
            result = subprocess.run(
                ['netsh', 'interface', 'show', 'interface'],
                capture_output=True,
                text=True,
                timeout=3,
                encoding='utf-8',
                errors='ignore'
            )
        except Exception:
            return None

        if result.returncode != 0:
            return None

        snapshot = {}

        for raw_line in result.stdout.splitlines():
            line = raw_line.strip()
            if not line or line.startswith('-'):
                continue
            if 'Interface Name' in line or '接口名称' in line:
                continue

            parts = re.split(r'\s{2,}', line)
            if len(parts) < 4:
                continue

            admin_state, state, iface_kind = parts[0], parts[1], parts[2].strip().lower()
            if iface_kind in {'loopback', 'internal', '环回', '内部'}:
                continue
            iface_name = parts[-1].strip()
            snapshot[iface_name] = self._normalize_windows_interface_state(admin_state, state)

        return snapshot

    def get_network_snapshot(self):
        if os.name == 'nt':
            return self._get_windows_network_snapshot()
        if sys.platform.startswith('linux'):
            return self._get_linux_network_snapshot()
        return None

    def _is_connected_state(self, state):
        return state == 'connected'

    def _get_connected_interfaces(self, snapshot):
        return [iface for iface, state in snapshot.items() if self._is_connected_state(state)]

    def _humanize_interface_state(self, state):
        state_map = {
            'connected': '已连接',
            'disconnected': '未连接',
            'disabled': '已禁用',
            'connecting': '连接中',
            'up': 'up',
            'down': 'down',
            'dormant': '休眠',
            'lowerlayerdown': '下层链路断开',
            'notpresent': '设备不存在',
            'unknown': '未知'
        }
        return state_map.get(state, state)

    def _format_interface_list(self, interfaces):
        return ", ".join(interfaces) if interfaces else "无"

    def _format_snapshot_summary(self, snapshot):
        if not snapshot:
            return "未获取到网络接口状态"
        items = []
        for iface in sorted(snapshot):
            items.append(f"{iface}[{self._humanize_interface_state(snapshot[iface])}]")
        return ", ".join(items)

    def _describe_network_changes(self, old_snapshot, new_snapshot):
        changes = []
        for iface in sorted(set(old_snapshot) | set(new_snapshot)):
            old_state = old_snapshot.get(iface)
            new_state = new_snapshot.get(iface)
            if old_state == new_state:
                continue
            if old_state is None:
                changes.append(f"{iface}: 新增 -> {self._humanize_interface_state(new_state)}")
            elif new_state is None:
                changes.append(f"{iface}: {self._humanize_interface_state(old_state)} -> 已移除")
            else:
                changes.append(
                    f"{iface}: {self._humanize_interface_state(old_state)} -> {self._humanize_interface_state(new_state)}"
                )
        return changes

    def check_network_state(self):
        snapshot = self.get_network_snapshot()
        if snapshot is None:
            return None, [], None, []
        if not snapshot:
            return None, [], {}, []
        connected_interfaces = self._get_connected_interfaces(snapshot)
        is_connected = bool(connected_interfaces)
        changes = self._describe_network_changes(self.last_network_snapshot, snapshot)
        return is_connected, connected_interfaces, snapshot, changes

    def _handle_portal_redirect(self, location):
        if 'eportal' in location or 'upc.edu.cn' in location:
            self.ref_url = location
            self._parse_portal_from_ref()
            return False
        return None

    def _is_portal_like_url(self, url):
        target = (url or "").lower()
        portal_tokens = (
            'eportal',
            'interface.do?method=login',
            'upc.edu.cn',
            'wlanuserip=',
            'wlanacip=',
        )
        return any(token in target for token in portal_tokens)

    def _is_portal_like_payload(self, payload):
        body = (payload or "").lower()
        portal_tokens = (
            'eportal',
            'interface.do?method=login',
            'wlanuserip=',
            'wlanacip=',
            'campus net',
            'portal',
        )
        return any(token in body for token in portal_tokens)

    def _parse_login_response(self, res_text):
        try:
            data = json.loads(res_text)
        except Exception:
            return "", res_text.strip(), None

        result = str(data.get('result', '')).strip().lower()
        message = str(
            data.get('message')
            or data.get('msg')
            or data.get('resultDescribe')
            or data.get('reason')
            or ''
        ).strip()
        return result, message, data

    def _schedule_login_retry(self, delay_seconds, reason, level="!"):
        delay_seconds = max(1, int(delay_seconds))
        self.login_retry_at = time.time() + delay_seconds
        self.login_retry_reason = reason
        self.login_retry_notice_at = 0.0
        self.log(f"自动认证暂停 {delay_seconds}s 后再试: {reason}", level)

    def _remaining_login_retry_seconds(self):
        return max(0, int(self.login_retry_at - time.time()))

    def _maybe_log_login_retry_wait(self):
        remaining = self._remaining_login_retry_seconds()
        if remaining <= 0:
            return False

        now = time.time()
        if self.login_retry_notice_at == 0.0 or now - self.login_retry_notice_at >= 15:
            reason = self.login_retry_reason or "等待下一次自动重试窗口"
            self.log(f"跳过本轮自动认证，{remaining}s 后再试。原因: {reason}", "!")
            self.login_retry_notice_at = now
        return True

    def _get_retry_sleep_seconds(self, default_seconds=3):
        remaining = self._remaining_login_retry_seconds()
        if remaining <= 0:
            return default_seconds
        return max(2, min(remaining, 15))

    def _classify_login_failure(self, message):
        permanent_keywords = (
            '设备未注册',
            '账号或密码错误',
            '密码错误',
            '用户不存在',
            '账号不存在',
            '无权限',
            '已欠费',
            '黑名单',
            '停机',
            '设备数已满',
        )
        for keyword in permanent_keywords:
            if keyword in message:
                return 'permanent'
        return 'transient'

    def _handle_login_failure(self, message, fallback_delay=None):
        clean_message = (message or "网关返回未知错误").strip()
        failure_kind = self._classify_login_failure(clean_message)

        if failure_kind == 'permanent':
            self._schedule_login_retry(
                self.login_permanent_retry_delay,
                f"网关明确拒绝: {clean_message}",
                "!"
            )
            return False

        retry_delay = fallback_delay if fallback_delay is not None else self.login_retry_backoff
        self._schedule_login_retry(retry_delay, f"认证失败: {clean_message}", "!")
        self.login_retry_backoff = min(self.login_retry_backoff * 2, self.login_retry_backoff_max)
        return False

    def _http_probe(self, host, ip=None, timeout=None, success_markers=(), allow_non_portal_success=False):
        test_url = f"http://{ip or host}"
        headers = self.req_header.copy()
        if ip and ip != host:
            headers['Host'] = host

        req = urllib.request.Request(test_url, headers=headers)

        try:
            response = self.opener.open(req, timeout=timeout or self.http_probe_timeout)
            status_code = response.getcode()
            payload = response.read(1024).decode('utf-8', errors='ignore')
            probe_text = f"{response.url}\n{payload}"
            if not success_markers or any(marker in probe_text for marker in success_markers):
                return True
            if allow_non_portal_success and status_code in (200, 204):
                if not self._is_portal_like_url(response.url) and not self._is_portal_like_payload(payload):
                    return True
        except urllib.error.HTTPError as e:
            if e.code in (301, 302, 303, 307):
                location = e.headers.get('Location', '')
                redirected = self._handle_portal_redirect(location)
                if redirected is False:
                    return False
                if allow_non_portal_success and location and not self._is_portal_like_url(location):
                    return True
        except Exception:
            pass

        return None

    def _portal_domains_in_order(self):
        ordered = []
        if self.active_domain:
            ordered.append(self.active_domain)
        for domain in self.domains:
            if domain not in ordered:
                ordered.append(domain)
        return ordered

    def _probe_external_network(self):
        if self.external_probe_ip:
            result = self._http_probe(
                host=self.external_probe_host,
                ip=self.external_probe_ip,
                success_markers=('baidu.com', '百度'),
                allow_non_portal_success=True
            )
            if result is True:
                return True
            if result is False:
                return False

        resolved_ip = self.resolve_domain(self.external_probe_host)
        if resolved_ip and resolved_ip != self.external_probe_ip:
            result = self._http_probe(
                host=self.external_probe_host,
                ip=resolved_ip,
                success_markers=('baidu.com', '百度'),
                allow_non_portal_success=True
            )
            if result is True:
                self.external_probe_ip = resolved_ip
                return True
            if result is False:
                return False

        result = self._http_probe(
            host=self.external_probe_host,
            success_markers=('baidu.com', '百度'),
            allow_non_portal_success=True
        )
        if result is True:
            return True
        if result is False:
            return False

        return None

    def _probe_portal_status(self):
        for domain in self._portal_domains_in_order():
            cached_ip = self.portal_ip if domain == self.active_domain and self.portal_ip else ""
            if cached_ip:
                result = self._http_probe(
                    host=domain,
                    ip=cached_ip,
                    success_markers=('success',)
                )
                if result is True:
                    self.active_domain = domain
                    self.portal_ip = cached_ip
                    return True
                if result is False:
                    self.active_domain = domain
                    return False

            resolved_ip = self.resolve_domain(domain)
            if resolved_ip and resolved_ip != cached_ip:
                result = self._http_probe(
                    host=domain,
                    ip=resolved_ip,
                    success_markers=('success',)
                )
                if result is True:
                    self.active_domain = domain
                    self.portal_ip = resolved_ip
                    return True
                if result is False:
                    self.active_domain = domain
                    self.portal_ip = resolved_ip
                    return False

            if not cached_ip and not resolved_ip:
                result = self._http_probe(
                    host=domain,
                    success_markers=('success',)
                )
                if result is True:
                    self.active_domain = domain
                    return True
                if result is False:
                    self.active_domain = domain
                    return False

        return False

    def check_status(self):
        external_status = self._probe_external_network()
        if external_status is not None:
            return external_status

        return self._probe_portal_status()

    def login(self):
        if not self.load_config():
            self.log("找不到账号凭据，请稍后按 [x] 进行配置", "-")
            return False

        if self._maybe_log_login_retry_wait():
            return False

        query_string = self._get_portal_query_string()

        post_data = {
            'userId': self.current_uid,
            'password': self.current_pwd,
            'service': self.current_srv,
            'queryString': query_string,
            'operatorPwd': '',
            'operatorUserId': '',
            'validcode': '',
            'passwordEncrypt': 'false'
        }

        login_base = self._get_portal_connect_origin()
        if not login_base:
            self.log("未捕获到有效 Portal URL，暂时无法发送认证包。", "-")
            return False

        login_url = urllib.parse.urljoin(login_base, self.login_path)
        headers = {
            **self.req_header, 
            'Host': self.portal_netloc or self.active_domain,
            'Origin': self._get_origin_header(),
            'Referer': self.ref_url or self._get_origin_header(),
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'
        }
        
        post_data_byte = urllib.parse.urlencode(post_data).encode()
        req = urllib.request.Request(login_url, headers=headers, data=post_data_byte, method='POST')
        
        self.log(f"正在发送认证包 (当前账号: {self.current_uid})...", "*")
        try:
            # 使用无重定向的 opener
            response = self.opener.open(req, timeout=self.login_timeout)
            res_text = response.read().decode('utf-8', errors='ignore')
            result, message, _ = self._parse_login_response(res_text)

            # ePortal 常见返回为 200 JSON
            if result in ('success', 'ok', 'login_ok') or 'success' in res_text or 'login_ok' in res_text:
                self.reset_login_retry_state()
                self.log(f"✅ 账号 [{self.current_uid}] 认证请求返回成功！", "+")
                return True

            return self._handle_login_failure(message or res_text[:120])
                
        except urllib.error.HTTPError as e:
            # 斩断 POST 后可能发生的 302 成功跳转（防无限死循环）
            if e.code in (301, 302, 303, 307):
                loc = e.headers.get('Location', '')
                self.reset_login_retry_state()
                self.log(f"[*] 收到网关跳转指令 (HTTP {e.code}) -> {loc[:30]}...", "*")
                self.log(f"✅ 假定认证已提交，交由心跳检测复核真实状态。", "+")
                return True 
            else:
                return self._handle_login_failure(f"HTTP {e.code}", fallback_delay=self.login_retry_backoff)
        except Exception as e:
            return self._handle_login_failure(f"网络底层异常或连接重置: {e}", fallback_delay=self.login_retry_backoff)

    def monitor_daemon(self):
        self.log("执行初次网络探测...", "*")

        link_up, interfaces, snapshot, _ = self.check_network_state()
        self.last_link_status = link_up
        if snapshot is not None:
            self.last_network_snapshot = snapshot

        if link_up is False:
            summary = self._format_snapshot_summary(snapshot)
            self.log(f"⚠️ 启动时网络未连接，等待状态变化后再继续探测... ({summary})", "!")
            self.last_status = False
        elif link_up is None:
            self.log("⚠️ 本机网络状态暂不可读，回退到外网探测判断连通性。", "!")
            if self.check_status():
                acc_info = f"账号: {self.current_uid}" if self.current_uid else "未配置账号"
                self.log(f"✅ 启动时外网畅通！进入静默心跳 ({acc_info})...", "+")
                self.last_status = True
            else:
                self.log("❌ 启动时外网未通或需要认证，准备自动认证...", "-")
                self.last_status = False
        elif self.check_status():
            acc_info = f"账号: {self.current_uid}" if self.current_uid else "未配置账号"
            iface_info = self._format_interface_list(interfaces)
            self.log(f"✅ 启动时外网畅通！进入静默心跳 ({acc_info}, 网卡: {iface_info})...", "+")
            self.last_status = True
        else:
            iface_info = self._format_interface_list(interfaces)
            self.log(f"❌ 启动时外网未通或需要认证，准备自动认证... (网卡: {iface_info})", "-")
            self.last_status = False

        while True:
            if self.in_config_mode:
                time.sleep(1)
                continue

            link_up, interfaces, snapshot, changes = self.check_network_state()

            if changes:
                self.reset_login_retry_state()
                self.log(f"检测到网络状态变化: {'; '.join(changes)}", "!")

            if link_up is False:
                if self.last_link_status is not False:
                    summary = self._format_snapshot_summary(snapshot)
                    self.log(f"⚠️ 当前网络未连接，暂停认证与外网探测。({summary})", "!")
                self.last_link_status = False
                if snapshot is not None:
                    self.last_network_snapshot = snapshot
                self.last_status = False
                time.sleep(2)
                continue

            if link_up is None:
                self.last_link_status = None
            elif self.last_link_status is False:
                iface_info = self._format_interface_list(interfaces)
                self.log(f"✅ 网络已恢复连接，继续探测网络状态。({iface_info})", "+")

            if link_up is not None:
                self.last_link_status = link_up
            if snapshot is not None:
                self.last_network_snapshot = snapshot

            current_status = self.check_status()
            
            if self.in_config_mode: continue 

            if not current_status:
                if self.last_status is True:
                    self.log("⚠️ 外网访问异常或认证失效，触发重新认证！", "!")
                self.last_status = False
                
                if self.ref_url:
                    login_ok = self.login()
                    time.sleep(2 if login_ok else self._get_retry_sleep_seconds())
                else:
                    time.sleep(3)
            else:
                self.reset_login_retry_state()
                if self.last_status is False:
                    acc_info = f"当前账号: {self.current_uid}" if self.current_uid else "配置丢失"
                    self.log(f"✅ 网络链路恢复，下潜至后台监测 [{acc_info}]", "+")
                self.last_status = True
                
                if not self.in_config_mode:
                    self.log(f"Ping Baidu -> HTTP 200 OK (User: {self.current_uid})", "+", inline=True)
                time.sleep(3)

    def run(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        print("\033[36m" + "="*50)
        print("          UPC Campus Net Auto-Login Daemon        ")
        print("="*50 + "\033[0m")
        
        self.load_config() 
        
        if not self.current_uid:
            self.log("未检测到配置文件，进入初始化引导...", "!")
            self.interactive_setup()
            
        self.log("守护进程拉起。运行中随时可输入 [x] 并回车修改配置。", "*")
        
        threading.Thread(target=self.monitor_daemon, daemon=True).start()

        try:
            while True:
                cmd = sys.stdin.readline().strip()
                if cmd.lower() == 'x':
                    self.interactive_setup()
        except KeyboardInterrupt:
            print("\n\033[33m[!] 收到退出信号 (SIGINT)，再见！\033[0m")
            os._exit(0)

if __name__ == '__main__':
    UPCPortal().run()
