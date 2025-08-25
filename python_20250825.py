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
ARGO_PID_FILE = INSTALL_DIR / "sbargopid.log"
LIST_FILE = INSTALL_DIR / "list.txt"
LOG_FILE = INSTALL_DIR / "argo.log"
SB_LOG_FILE = INSTALL_DIR / "sb.log"
SINGBOX_CONFIG_FILE = INSTALL_DIR / "singbox_client_config.json"
ALL_NODES_FILE = INSTALL_DIR / "allnodes.txt"

# --- 辅助函数 ---

def get_latest_singbox_version():
    """获取最新的sing-box稳定版本号。"""
    try:
        req = urllib.request.Request(
            "https://api.github.com/repos/SagerNet/sing-box/releases/latest",
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode())
            version = data['tag_name'].lstrip('v')
            return version
    except Exception as e:
        st.warning(f"无法获取最新版本，使用默认版本: {e}")
        return "1.10.1"  # 默认使用较新的稳定版本

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
        "v": "2",
        "ps": config.get("ps"),
        "add": config.get("add"),
        "port": str(config.get("port")),
        "id": config.get("id"),
        "aid": "0",
        "scy": "auto",
        "net": "ws",
        "type": "none",
        "host": config.get("host"),
        "path": "/",
        "tls": "tls",
        "sni": config.get("sni"),
        "alpn": "h2,http/1.1",
        "fp": "chrome"
    }
    vmess_str = json.dumps(vmess_obj, separators=(',', ':'))
    return f"vmess://{base64.b64encode(vmess_str.encode('utf-8')).decode('utf-8').rstrip('=')}"

def get_tunnel_domain():
    """从argo日志中获取临时隧道域名。"""
    for _ in range(15):
        if LOG_FILE.exists():
            try:
                log_content = LOG_FILE.read_text()
                match = re.search(r'https://([a-zA-Z0-9.-]+\.trycloudflare\.com)', log_content)
                if match: return match.group(1)
            except Exception: pass
        time.sleep(2)
    return None

def stop_services():
    """停止所有相关服务进程。"""
    for pid_file in [SB_PID_FILE, ARGO_PID_FILE]:
        if pid_file.exists():
            try:
                pid = int(pid_file.read_text().strip())
                os.kill(pid, 9)
            except (ValueError, ProcessLookupError, FileNotFoundError): pass
            finally: pid_file.unlink(missing_ok=True)
    subprocess.run("pkill -9 -f 'sing-box run'", shell=True, capture_output=True)
    subprocess.run("pkill -9 -f 'cloudflared tunnel'", shell=True, capture_output=True)

# --- 核心逻辑 ---

def generate_all_configs(domain, uuid_str, port_vm_ws):
    """生成所有节点链接和客户端配置文件，并返回用于UI显示的文本。"""
    hostname = socket.gethostname()[:10]
    all_links = []
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
    
    ALL_NODES_FILE.write_text("\n".join(all_links) + "\n")

    list_output_text = f"""
✅ **服务已启动**
---
- **域名 (Domain):** `{domain}`
- **UUID:** `{uuid_str}`
- **本地端口:** `{port_vm_ws}`
- **WebSocket路径:** `/`
---
**Vmess 链接 (可复制):**
""" + "\n".join(all_links)
    
    LIST_FILE.write_text(list_output_text)
    return list_output_text

def start_services(uuid_str, port_vm_ws, custom_domain, argo_token):
    """核心函数：根据Secrets中的配置，安装并启动服务。"""
    with st.spinner("正在停止任何可能残留的旧服务..."):
        stop_services()
    
    try:
        INSTALL_DIR.mkdir(parents=True, exist_ok=True)
        
        # 补全可能为空的配置
        uuid_str = uuid_str or str(uuid.uuid4())
        port_vm_ws = port_vm_ws or random.randint(10000, 65535)

        with st.spinner("正在检查并安装依赖 (sing-box, cloudflared)..."):
            arch = "amd64" if "x86_64" in platform.machine().lower() else "arm64"
            singbox_path = INSTALL_DIR / "sing-box"
            
            # 获取最新版本并下载sing-box
            if not singbox_path.exists():
                sb_version = get_latest_singbox_version()
                sb_name_actual = f"sing-box-{sb_version}-linux-{arch}"
                tar_path = INSTALL_DIR / "sing-box.tar.gz"
                
                download_url = f"https://github.com/SagerNet/sing-box/releases/download/v{sb_version}/{sb_name_actual}.tar.gz"
                if not download_file(download_url, tar_path):
                    return False, "sing-box 下载失败。"
                
                import tarfile
                with tarfile.open(tar_path, "r:gz") as tar:
                    tar.extractall(path=INSTALL_DIR)
                shutil.move(INSTALL_DIR / sb_name_actual / "sing-box", singbox_path)
                shutil.rmtree(INSTALL_DIR / sb_name_actual)
                tar_path.unlink()
                os.chmod(singbox_path, 0o755)

            cloudflared_path = INSTALL_DIR / "cloudflared"
            if not cloudflared_path.exists():
                cf_arch = "amd64" if arch == "amd64" else "arm"
                if not download_file(
                    f"https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-{cf_arch}",
                    cloudflared_path
                ):
                    return False, "cloudflared 下载失败。"
                os.chmod(cloudflared_path, 0o755)

        with st.spinner("正在根据您的配置启动服务..."):
            # 优化的sing-box配置，支持视频流
            sb_config = {
                "log": {
                    "level": "info",
                    "timestamp": True
                },
                "dns": {
                    "servers": [
                        {
                            "tag": "google",
                            "address": "tls://8.8.8.8"
                        },
                        {
                            "tag": "local",
                            "address": "223.5.5.5",
                            "detour": "direct"
                        }
                    ],
                    "strategy": "ipv4_only",
                    "disable_cache": False
                },
                "inbounds": [{
                    "type": "vmess",
                    "tag": "vmess-in",
                    "listen": "127.0.0.1",
                    "listen_port": port_vm_ws,
                    "sniff": True,
                    "sniff_override_destination": True,
                    "domain_strategy": "ipv4_only",
                    "users": [{
                        "uuid": uuid_str,
                        "alterId": 0
                    }],
                    "transport": {
                        "type": "ws",
                        "path": "/",
                        "max_early_data": 2048,
                        "early_data_header_name": "Sec-WebSocket-Protocol"
                    }
                }],
                "outbounds": [
                    {
                        "type": "direct",
                        "tag": "direct"
                    },
                    {
                        "type": "dns",
                        "tag": "dns-out"
                    }
                ],
                "route": {
                    "rules": [
                        {
                            "protocol": "dns",
                            "outbound": "dns-out"
                        },
                        {
                            "geosite": "cn",
                            "geoip": ["cn", "private"],
                            "outbound": "direct"
                        }
                    ],
                    "auto_detect_interface": True
                },
                "experimental": {
                    "clash_api": {
                        "external_controller": "127.0.0.1:9090",
                        "external_ui": "ui",
                        "store_selected": True
                    }
                }
            }
            
            (INSTALL_DIR / "sb.json").write_text(json.dumps(sb_config, indent=2))
            
            with open(SB_LOG_FILE, "w") as sb_log:
                sb_process = subprocess.Popen(
                    [str(singbox_path), 'run', '-c', 'sb.json'],
                    cwd=INSTALL_DIR,
                    stdout=sb_log,
                    stderr=subprocess.STDOUT
                )
            SB_PID_FILE.write_text(str(sb_process.pid))
            
            # 启动cloudflared
            if argo_token:
                cf_cmd = [
                    str(cloudflared_path), 'tunnel', '--no-autoupdate',
                    'run', '--token', argo_token
                ]
            else:
                cf_cmd = [
                    str(cloudflared_path), 'tunnel', '--no-autoupdate',
                    '--url', f'http://localhost:{port_vm_ws}',
                    '--protocol', 'http2'
                ]
            
            with open(LOG_FILE, "w") as cf_log:
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

        links_output = generate_all_configs(final_domain, uuid_str, port_vm_ws)
        return True, links_output
    
    except Exception as e:
        return False, f"处理过程中发生意外错误: {e}"

def uninstall_services():
    """卸载服务，清理所有运行时文件。"""
    stop_services()
    if INSTALL_DIR.exists():
        shutil.rmtree(INSTALL_DIR)
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
        "本地端口": config["port_vm_ws"] or "将随机选择",
        "自定义域名": config["custom_domain"] or "将使用Cloudflare临时域名",
        "Argo Token": "********" if config["argo_token"] else "未提供"
    })

    st.markdown("---")
    st.subheader("控制操作")
    
    c1, c2 = st.columns(2)
    if c1.button("🚀 启动/重启服务", type="primary", use_container_width=True):
        success, message = start_services(
            config["uuid_str"],
            config["port_vm_ws"],
            config["custom_domain"],
            config["argo_token"]
        )
        if success:
            st.session_state.output = message
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
        
        # 添加复制按钮和使用提示
        st.markdown("---")
        st.subheader("使用提示")
        st.info("""
        **v2rayN 使用说明：**
        1. 复制上面的任意一个 vmess:// 链接
        2. 在 v2rayN 中点击"服务器" -> "从剪贴板导入批量URL"
        3. 选择导入的节点，右键点击"设为活动服务器"
        4. 确保系统代理已开启
        
        **如果YouTube视频无法播放：**
        - 尝试切换不同的节点（不同的IP地址）
        - 在 v2rayN 设置中启用"Mux多路复用"
        - 检查系统时间是否准确
        """)

def render_login_ui(secret_key):
    """渲染伪装的登录界面。"""
    st.set_page_config(page_title="天气查询", layout="centered")
    st.title("🌦️ 实时天气查询")
    st.markdown("---")
    
    # 添加一些伪装元素
    col1, col2 = st.columns([2, 1])
    with col1:
        city = st.text_input("请输入城市名或秘密口令：", "Beijing", key="city_input")
    with col2:
        st.markdown("<br>", unsafe_allow_html=True)
        query_button = st.button("查询天气", use_container_width=True)
    
    # 添加天气图标装饰
    st.markdown("""
    <div style='text-align: center; padding: 20px;'>
        <span style='font-size: 48px;'>☀️ 🌤️ ⛅ 🌦️ 🌧️</span>
    </div>
    """, unsafe_allow_html=True)
    
    if query_button:
        if city == secret_key:
            st.session_state.authenticated = True
            st.rerun()
        else:
            with st.spinner(f"正在查询 {city} 的天气..."):
                time.sleep(1)
            st.error(f"无法获取 {city} 的天气信息，请检查城市名称是否正确。")
            
            # 显示假的天气信息
            st.info("提示：请输入正确的城市名称，如 Beijing, Shanghai, Guangzhou 等。")

def main():
    """主应用逻辑。"""
    # 初始化session state
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'output' not in st.session_state:
        st.session_state.output = ""
    
    # 从 Streamlit Secrets 读取所有配置
    try:
        secret_key = st.secrets["SECRET_KEY"]
        config = {
            "uuid_str": st.secrets.get("UUID_STR", ""),
            "port_vm_ws": int(st.secrets.get("PORT_VM_WS", 0)) if st.secrets.get("PORT_VM_WS") else 0,
            "custom_domain": st.secrets.get("CUSTOM_DOMAIN", ""),
            "argo_token": st.secrets.get("ARGO_TOKEN", "")
        }
    except KeyError as e:
        st.error(f"错误：未在 Secrets 中找到必需的配置项: {e}")
        st.info("""
        请确保您已创建 `.streamlit/secrets.toml` 文件并包含以下配置：
        ```toml
        SECRET_KEY = "your-secret-key"
        UUID_STR = ""  # 可选，留空将自动生成
        PORT_VM_WS = 0  # 可选，0表示随机端口
        CUSTOM_DOMAIN = ""  # 可选
        ARGO_TOKEN = ""  # 可选
        ```
        """)
        st.stop()
        return
    except Exception as e:
        st.error(f"读取配置时发生错误: {e}")
        st.stop()
        return
    
    # 根据认证状态显示不同界面
    if st.session_state.authenticated:
        render_main_ui(config)
    else:
        render_login_ui(secret_key)

if __name__ == "__main__":
    main()
