#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# 导入必要的库
import os
import json
import random
import time
import shutil
import re
import base64
import socket
import subprocess
import platform
import uuid
from pathlib import Path
import urllib.request
import streamlit as st

# --- 全局常量定义 ---
# 工作目录，用于存放运行时产生的文件
INSTALL_DIR = Path.home() / ".agsb"
# 运行时生成的各种文件路径
SB_PID_FILE = INSTALL_DIR / "sbpid.log"
HYSTERIA_PID_FILE = INSTALL_DIR / "hysteria_pid.log"
ARGO_PID_FILE = INSTALL_DIR / "sbargopid.log"
LIST_FILE = INSTALL_DIR / "list.txt"
LOG_FILE = INSTALL_DIR / "argo.log"
SB_LOG_FILE = INSTALL_DIR / "sb.log"
HYSTERIA_LOG_FILE = INSTALL_DIR / "hysteria.log"
SINGBOX_CONFIG_FILE = INSTALL_DIR / "singbox_client_config.json"
ALL_NODES_FILE = INSTALL_DIR / "allnodes.txt"

# --- 辅助函数 ---

def download_file(url, target_path):
    """下载文件并显示进度。"""
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as response, open(target_path, 'wb') as out_file:
            shutil.copyfileobj(response, out_file)
        return True
    except Exception as e:
        st.error(f"下载失败: {url}, 错误: {e}")
        return False

def generate_vmess_link(config):
    """生成Vmess链接。"""
    vmess_obj = {
        "v": "2", "ps": config.get("ps"), "add": config.get("add"), "port": str(config.get("port")),
        "id": config.get("id"), "aid": "0", "scy": "auto", "net": "ws", "type": "none",
        "host": config.get("host"), "path": "/", "tls": "tls", "sni": config.get("sni")
    }
    vmess_str = json.dumps(vmess_obj, separators=(',', ':'))
    return f"vmess://{base64.b64encode(vmess_str.encode('utf-8')).decode('utf-8').rstrip('=')}"

def generate_hysteria_link(domain, port, auth_str, peer, insecure=1):
    """生成Hysteria链接。"""
    # hysteria://domain:port?protocol=udp&auth=auth_str&peer=peer&insecure=1#remark
    remark = f"HY-{domain}"
    link = f"hysteria://{domain}:{port}?protocol=udp&auth={auth_str}&peer={peer}&insecure={insecure}#{remark}"
    return link

def get_tunnel_domain():
    """从argo日志中获取临时隧道域名。"""
    for _ in range(15):
        if LOG_FILE.exists():
            try:
                log_content = LOG_FILE.read_text(encoding='utf-8')
                match = re.search(r'https://([a-zA-Z0-9.-]+\.trycloudflare\.com)', log_content)
                if match: return match.group(1)
            except Exception: pass
        time.sleep(2)
    return None

def stop_services():
    """停止所有相关服务进程。"""
    # 根据操作系统选择不同的终止进程方法
    system = platform.system()
    
    for pid_file in [SB_PID_FILE, HYSTERIA_PID_FILE, ARGO_PID_FILE]:
        if pid_file.exists():
            try:
                pid = int(pid_file.read_text().strip())
                if system == "Windows":
                    subprocess.run(f"taskkill /F /PID {pid}", shell=True, capture_output=True)
                else:
                    os.kill(pid, 9)
            except (ValueError, ProcessLookupError, FileNotFoundError): pass
            finally: pid_file.unlink(missing_ok=True)
    
    # 终止相关进程
    try:
        if system == "Windows":
            subprocess.run("taskkill /F /IM sing-box.exe", shell=True, capture_output=True)
            subprocess.run("taskkill /F /IM hysteria.exe", shell=True, capture_output=True)
            subprocess.run("taskkill /F /IM cloudflared.exe", shell=True, capture_output=True)
        else:
            subprocess.run("pkill -9 -f 'sing-box run'", shell=True, capture_output=True)
            subprocess.run("pkill -9 -f 'hysteria server'", shell=True, capture_output=True)
            subprocess.run("pkill -9 -f 'cloudflared tunnel'", shell=True, capture_output=True)
    except Exception: pass

# --- 核心逻辑 ---

def generate_all_configs(domain, uuid_str, port_vm_ws, hysteria_port, hysteria_auth):
    """生成所有节点链接和客户端配置文件，并返回用于UI显示的文本。"""
    hostname = socket.gethostname()[:10]
    all_links = []
    
    # 生成Vmess链接
    cf_ips_tls = {
        "104.16.0.0": "443", 
        "104.17.0.0": "8443", 
        "104.18.0.0": "2053", 
        "104.19.0.0": "2083", 
        "104.20.0.0": "2087"
    }
    
    for ip, port in cf_ips_tls.items():
        all_links.append(generate_vmess_link({
            "ps": f"VMWS-TLS-{hostname}-{ip.split('.')[2]}-{port}", 
            "add": ip, 
            "port": port, 
            "id": uuid_str, 
            "host": domain, 
            "sni": domain
        }))
    
    all_links.append(generate_vmess_link({
        "ps": f"VMWS-TLS-Direct-{hostname}", 
        "add": domain, 
        "port": "443", 
        "id": uuid_str, 
        "host": domain, 
        "sni": domain
    }))
    
    # 生成Hysteria链接
    all_links.append(generate_hysteria_link(
        domain=domain,
        port=hysteria_port,
        auth_str=hysteria_auth,
        peer=domain,
        insecure=1
    ))
    
    ALL_NODES_FILE.write_text("\n".join(all_links) + "\n", encoding='utf-8')

    list_output_text = f"""
✅ **服务已启动**
---
- **域名 (Domain):** `{domain}`
- **Vmess UUID:** `{uuid_str}`
- **Vmess 本地端口:** `{port_vm_ws}`
- **Hysteria 端口:** `{hysteria_port}`
- **Hysteria 密码:** `{hysteria_auth}`
- **WebSocket路径:** `/`
---
**节点链接 (可复制):**
""" + "\n".join(all_links)
    
    LIST_FILE.write_text(list_output_text, encoding='utf-8')
    
    # 生成singbox客户端配置
    singbox_config = {
        "log": {"level": "info"},
        "dns": {
            "servers": [
                {
                    "tag": "google",
                    "address": "tls://8.8.8.8"
                }
            ]
        },
        "inbounds": [],
        "outbounds": [
            {
                "type": "vmess",
                "tag": "proxy-vmess",
                "server": domain,
                "server_port": 443,
                "uuid": uuid_str,
                "security": "auto",
                "alter_id": 0,
                "global_padding": False,
                "authenticated_length": True,
                "transport": {
                    "type": "ws",
                    "path": "/",
                    "headers": {
                        "Host": domain
                    }
                },
                "tls": {
                    "enabled": True,
                    "server_name": domain,
                    "insecure": True
                }
            },
            {
                "type": "hysteria",
                "tag": "proxy-hysteria",
                "server": domain,
                "server_port": int(hysteria_port),
                "up_mbps": 100,
                "down_mbps": 100,
                "auth_str": hysteria_auth,
                "tls": {
                    "enabled": True,
                    "server_name": domain,
                    "insecure": True
                }
            },
            {
                "type": "direct",
                "tag": "direct"
            }
        ],
        "route": {
            "rules": [
                {
                    "ip_cidr": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
                    "outbound": "direct"
                }
            ],
            "final": "proxy-vmess"
        }
    }
    
    SINGBOX_CONFIG_FILE.write_text(json.dumps(singbox_config, indent=2, ensure_ascii=False), encoding='utf-8')
    
    # 生成hysteria客户端配置 (修复格式问题)
    hysteria_client_config = {
        "server": f"{domain}:{hysteria_port}",
        "auth": hysteria_auth,
        "bandwidth": {
            "up": "50 mbps",
            "down": "100 mbps"
        },
        "socks5": {
            "listen": "127.0.0.1:10808"
        },
        "http": {
            "listen": "127.0.0.1:10809"
        },
        "tls": {
            "sni": domain,
            "insecure": True
        }
    }
    
    (INSTALL_DIR / "hysteria_client.json").write_text(
        json.dumps(hysteria_client_config, indent=2, ensure_ascii=False), 
        encoding='utf-8'
    )
    
    return list_output_text

def start_services(uuid_str, port_vm_ws, custom_domain, argo_token, hysteria_port, hysteria_auth):
    """核心函数：根据Secrets中的配置，安装并启动服务。"""
    with st.spinner("正在停止任何可能残留的旧服务..."):
        stop_services()
    
    try:
        INSTALL_DIR.mkdir(parents=True, exist_ok=True)
        
        # 补全可能为空的配置
        uuid_str = uuid_str or str(uuid.uuid4())
        port_vm_ws = port_vm_ws or random.randint(10000, 65535)
        hysteria_port = hysteria_port or random.randint(10000, 65535)
        hysteria_auth = hysteria_auth or str(uuid.uuid4())
        
        # 确保端口不冲突
        if port_vm_ws == hysteria_port:
            hysteria_port = random.randint(10000, 65535)

        with st.spinner("正在检查并安装依赖 (sing-box, hysteria, cloudflared)..."):
            arch = platform.machine().lower()
            system = platform.system().lower()
            
            # 确定架构
            if "x86_64" in arch or "amd64" in arch:
                arch = "amd64"
            elif "arm" in arch or "aarch" in arch:
                arch = "arm64" if "64" in arch else "arm"
            else:
                arch = "amd64"  # 默认

            # 下载sing-box
            singbox_path = INSTALL_DIR / ("sing-box.exe" if system == "windows" else "sing-box")
            if not singbox_path.exists():
                sb_version = "1.9.0-beta.11"
                if system == "linux":
                    sb_name_actual = f"sing-box-{sb_version}-linux-{arch}"
                    tar_name = f"{sb_name_actual}.tar.gz"
                    url = f"https://github.com/SagerNet/sing-box/releases/download/v{sb_version}/{tar_name}"
                    tar_path = INSTALL_DIR / tar_name
                    
                    if not download_file(url, tar_path):
                        return False, "sing-box 下载失败。"
                        
                    import tarfile
                    with tarfile.open(tar_path, "r:gz") as tar:
                        tar.extractall(path=INSTALL_DIR)
                    shutil.move(INSTALL_DIR / sb_name_actual / "sing-box", singbox_path)
                    shutil.rmtree(INSTALL_DIR / sb_name_actual)
                    tar_path.unlink()
                elif system == "windows":
                    sb_name_actual = f"sing-box-{sb_version}-windows-{arch}"
                    zip_name = f"{sb_name_actual}.zip"
                    url = f"https://github.com/SagerNet/sing-box/releases/download/v{sb_version}/{zip_name}"
                    zip_path = INSTALL_DIR / zip_name
                    
                    if not download_file(url, zip_path):
                        return False, "sing-box 下载失败。"
                        
                    import zipfile
                    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                        zip_ref.extractall(INSTALL_DIR)
                    shutil.move(INSTALL_DIR / sb_name_actual / "sing-box.exe", singbox_path)
                    shutil.rmtree(INSTALL_DIR / sb_name_actual)
                    zip_path.unlink()
                else:
                    return False, f"不支持的操作系统: {system}"
                
                os.chmod(singbox_path, 0o755)

            # 下载hysteria (使用正确的版本格式)
            hysteria_path = INSTALL_DIR / ("hysteria.exe" if system == "windows" else "hysteria")
            if not hysteria_path.exists():
                hy_version = "app/v2.6.2"  # 使用正确的版本格式
                # 构建正确的下载链接
                if system == "linux":
                    if arch == "amd64":
                        url = f"https://github.com/apernet/hysteria/releases/download/{hy_version}/hysteria-linux-amd64"
                    elif arch == "arm64":
                        url = f"https://github.com/apernet/hysteria/releases/download/{hy_version}/hysteria-linux-arm64"
                    else:
                        url = f"https://github.com/apernet/hysteria/releases/download/{hy_version}/hysteria-linux-arm"  # 默认arm
                elif system == "windows":
                    if arch == "amd64":
                        url = f"https://github.com/apernet/hysteria/releases/download/{hy_version}/hysteria-windows-amd64.exe"
                    else:
                        url = f"https://github.com/apernet/hysteria/releases/download/{hy_version}/hysteria-windows-arm64.exe"
                else:
                    return False, f"不支持的操作系统: {system}"
                
                st.info(f"正在下载 Hysteria: {url}")
                if not download_file(url, hysteria_path):
                    return False, f"hysteria 下载失败: {url}"
                
                os.chmod(hysteria_path, 0o755)
                st.success("Hysteria 下载完成!")

            # 下载cloudflared
            cloudflared_path = INSTALL_DIR / ("cloudflared.exe" if system == "windows" else "cloudflared")
            if not cloudflared_path.exists():
                cf_arch = "amd64" if arch == "amd64" else "arm"  # Cloudflared对arm的命名
                if system == "linux":
                    url = f"https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-{cf_arch}"
                elif system == "windows":
                    url = f"https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-{cf_arch}.exe"
                else:
                    return False, f"不支持的操作系统: {system}"
                    
                if not download_file(url, cloudflared_path):
                    return False, "cloudflared 下载失败。"
                    
                os.chmod(cloudflared_path, 0o755)

        with st.spinner("正在根据您的配置启动服务..."):
            # 创建sing-box配置
            sb_config = {
                "log": {"level": "info"},
                "inbounds": [
                    {
                        "type": "vmess",
                        "tag": "vmess-in",
                        "listen": "127.0.0.1",
                        "listen_port": port_vm_ws,
                        "sniff": True,
                        "users": [{"uuid": uuid_str, "alterId": 0}],
                        "transport": {"type": "ws", "path": "/"}
                    }
                ],
                "outbounds": [{"type": "direct"}]
            }
            
            sb_config_path = INSTALL_DIR / "sb.json"
            sb_config_path.write_text(json.dumps(sb_config, indent=2), encoding='utf-8')
            
            # 创建hysteria配置
            hysteria_config = {
                "listen": f":{hysteria_port}",
                "tls": {
                    "cert": str(INSTALL_DIR / "tls.crt"),
                    "key": str(INSTALL_DIR / "tls.key")
                },
                "auth": {
                    "type": "password",
                    "password": hysteria_auth
                },
                "masquerade": {
                    "type": "proxy",
                    "proxy": {
                        "url": f"http://127.0.0.1:{port_vm_ws}",
                        "rewriteHost": True
                    }
                },
                "quic": {
                    "initStreamReceiveWindow": 8388608,
                    "maxStreamReceiveWindow": 8388608,
                    "initConnReceiveWindow": 20971520,
                    "maxConnReceiveWindow": 20971520,
                    "maxIdleTimeout": "30s",
                    "maxIncomingStreams": 1024,
                    "disablePathMTUDiscovery": False
                }
            }
            
            # 生成自签名证书（简化处理，实际使用中建议使用有效证书）
            cert_path = INSTALL_DIR / "tls.crt"
            key_path = INSTALL_DIR / "tls.key"
            if not cert_path.exists() or not key_path.exists():
                # 使用sing-box生成自签名证书
                subprocess.run([
                    str(singbox_path), "tls", "generate-cert",
                    "--domain", "localhost",
                    "--cert", str(cert_path),
                    "--key", str(key_path)
                ], cwd=INSTALL_DIR, capture_output=True)
            
            hysteria_config_path = INSTALL_DIR / "hysteria_server.json"
            hysteria_config_path.write_text(json.dumps(hysteria_config, indent=2), encoding='utf-8')
            
            # 启动sing-box
            with open(SB_LOG_FILE, "w", encoding='utf-8') as sb_log:
                sb_process = subprocess.Popen(
                    [str(singbox_path), 'run', '-c', 'sb.json'], 
                    cwd=INSTALL_DIR, 
                    stdout=sb_log, 
                    stderr=subprocess.STDOUT
                )
            SB_PID_FILE.write_text(str(sb_process.pid))
            
            # 启动hysteria
            with open(HYSTERIA_LOG_FILE, "w", encoding='utf-8') as hy_log:
                hy_process = subprocess.Popen(
                    [str(hysteria_path), 'server', '-c', 'hysteria_server.json'], 
                    cwd=INSTALL_DIR, 
                    stdout=hy_log, 
                    stderr=subprocess.STDOUT
                )
            HYSTERIA_PID_FILE.write_text(str(hy_process.pid))
            
            # 启动cloudflared
            if argo_token:
                cf_cmd = [str(cloudflared_path), 'tunnel', '--no-autoupdate', 'run', '--token', argo_token]
            else:
                cf_cmd = [str(cloudflared_path), 'tunnel', '--no-autoupdate', '--url', f'http://localhost:{port_vm_ws}', '--protocol', 'http2']
                
            with open(LOG_FILE, "w", encoding='utf-8') as cf_log:
                cf_process = subprocess.Popen(
                    cf_cmd, 
                    cwd=INSTALL_DIR, 
                    stdout=cf_log, 
                    stderr=subprocess.STDOUT
                )
            ARGO_PID_FILE.write_text(str(cf_process.pid))

        with st.spinner("正在获取隧道域名并生成节点信息..."):
            time.sleep(5)
            final_domain = custom_domain or (get_tunnel_domain() if not argo_token else None)
            if not final_domain:
                return False, "未能确定隧道域名。请检查日志 (`.agsb/argo.log`)。"

        links_output = generate_all_configs(final_domain, uuid_str, port_vm_ws, hysteria_port, hysteria_auth)
        return True, links_output
    
    except Exception as e:
        return False, f"处理过程中发生意外错误: {e}"

def uninstall_services():
    """卸载服务，清理所有运行时文件。"""
    with st.spinner("正在停止所有服务..."):
        stop_services()
        
    if INSTALL_DIR.exists():
        try:
            shutil.rmtree(INSTALL_DIR)
        except Exception as e:
            st.error(f"删除工作目录时出错: {e}")
            
    st.success("✅ 卸载完成。所有运行时文件和进程已清除。")
    st.session_state.clear()

# --- UI 渲染函数 ---

def render_main_ui(config):
    """渲染主控制面板。"""
    st.set_page_config(page_title="部署工具", layout="wide")
    st.header("⚙️ 服务管理面板")

    st.subheader("当前配置 (来自 Secrets)")
    st.info("配置已从您的 `secrets.toml` 文件中加载。如需修改，请直接编辑该文件并重启应用。")
    
    st.json({
        "UUID": config["uuid_str"] or "将自动生成",
        "Vmess端口": config["port_vm_ws"] or "将随机选择",
        "Hysteria端口": config["hysteria_port"] or "将随机选择",
        "Hysteria密码": config["hysteria_auth"] or "将自动生成",
        "自定义域名": config["custom_domain"] or "将使用Cloudflare临时域名",
        "Argo Token": "********" if config["argo_token"] else "未提供"
    })

    st.markdown("---")
    st.subheader("控制操作")
    
    c1, c2 = st.columns(2)
    if c1.button("🚀 启动/重启服务", type="primary", use_container_width=True):
        with st.spinner("正在启动服务..."):
            success, message = start_services(
                config["uuid_str"], 
                config["port_vm_ws"], 
                config["custom_domain"], 
                config["argo_token"],
                config["hysteria_port"],
                config["hysteria_auth"]
            )
        if success:
            st.session_state.output = message
            st.success("服务启动成功!")
        else:
            st.error(f"操作失败: {message}")
            st.session_state.output = message
        st.rerun()

    if c2.button("❌ 永久卸载服务", use_container_width=True):
        with st.spinner("正在执行卸载..."):
            uninstall_services()
        st.rerun()
    
    # 显示节点信息区域
    if 'output' in st.session_state and st.session_state.output:
        st.subheader("节点信息")
        st.code(st.session_state.output)
        
        # 提供文件下载
        if ALL_NODES_FILE.exists():
            nodes_content = ALL_NODES_FILE.read_text(encoding='utf-8')
            st.download_button(
                label="📥 下载所有节点链接",
                data=nodes_content,
                file_name="all_nodes.txt",
                mime="text/plain"
            )
        
        if SINGBOX_CONFIG_FILE.exists():
            config_content = SINGBOX_CONFIG_FILE.read_text(encoding='utf-8')
            st.download_button(
                label="📥 下载Singbox配置文件",
                data=config_content,
                file_name="singbox_client_config.json",
                mime="application/json"
            )
        
        hysteria_client_file = INSTALL_DIR / "hysteria_client.json"
        if hysteria_client_file.exists():
            hy_config_content = hysteria_client_file.read_text(encoding='utf-8')
            st.download_button(
                label="📥 下载Hysteria客户端配置",
                data=hy_config_content,
                file_name="hysteria_client.json",
                mime="application/json"
            )

def render_login_ui(secret_key):
    """渲染伪装的登录界面。"""
    st.set_page_config(page_title="天气查询", layout="centered")
    st.title("🌦️ 实时天气查询")
    city = st.text_input("请输入城市名或秘密口令：", "Beijing")
    if st.button("查询天气"):
        if city == secret_key:
            st.session_state.authenticated = True
            st.rerun()
        else:
            with st.spinner(f"正在查询 {city} 的天气..."):
                time.sleep(1)
            st.error("查询失败")

def main():
    """主应用逻辑。"""
    st.session_state.setdefault('authenticated', False)
    st.session_state.setdefault('output', "")
    
    # 从 Streamlit Secrets 读取所有配置
    try:
        secret_key = st.secrets["SECRET_KEY"]
        config = {
            "uuid_str": st.secrets.get("UUID_STR", ""),
            "port_vm_ws": st.secrets.get("PORT_VM_WS", 0),
            "hysteria_port": st.secrets.get("HYSTERIA_PORT", 0),
            "hysteria_auth": st.secrets.get("HYSTERIA_AUTH", ""),
            "custom_domain": st.secrets.get("CUSTOM_DOMAIN", ""),
            "argo_token": st.secrets.get("ARGO_TOKEN", "")
        }
    except KeyError:
        st.error("错误：未在 Secrets 中找到 'SECRET_KEY'。")
        st.info("请确保您已创建 `.streamlit/secrets.toml` 文件并正确设置了 `SECRET_KEY`。")
        return
        
    if st.session_state.authenticated:
        render_main_ui(config)
    else:
        render_login_ui(secret_key)

if __name__ == "__main__":
    main()
