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
import urllib.parse
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

# --- 辅助函数 (基本保持不变) ---

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

def generate_vless_reality_link(config):
    """生成VLESS Reality链接。"""
    # VLESS Reality 链接格式: vless://uuid@host:port?type=tcp&security=reality&pbk=publicKey&fp=firefox&flow=xtls-rprx-vision&sni=sniHost&sid=shortId#ps
    params = {
        "type": "tcp",
        "security": "reality",
        "pbk": config.get("public_key"),
        "fp": "chrome",  # 指纹，可选: chrome, firefox, safari, ios, android, edge, 360, qq
        "flow": "xtls-rprx-vision",
        "sni": config.get("sni"),
        "sid": config.get("short_id"),
        "spx": "/"
    }
    
    # 构建查询参数
    query_params = "&".join([f"{k}={urllib.parse.quote(str(v))}" for k, v in params.items()])
    
    # 构建完整链接
    vless_link = f"vless://{config.get('uuid')}@{config.get('host')}:{config.get('port')}?{query_params}#{urllib.parse.quote(config.get('ps'))}"
    
    return vless_link

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

# 生成随机密钥和ID的函数
def generate_reality_keys(singbox_path):
    """生成Reality所需的密钥和shortId"""
    try:
        # 生成私钥和公钥
        keypair_output = subprocess.run(
            [str(singbox_path), "generate", "reality-keypair"],
            cwd=INSTALL_DIR, capture_output=True, text=True, timeout=30
        )
        if keypair_output.returncode != 0:
            raise Exception(f"生成密钥对失败: {keypair_output.stderr}")
        
        private_key, public_key = keypair_output.stdout.strip().split('\t')
        
        # 生成shortId
        short_id_output = subprocess.run(
            [str(singbox_path), "generate", "rand", "--hex", "8"],
            cwd=INSTALL_DIR, capture_output=True, text=True, timeout=30
        )
        if short_id_output.returncode != 0:
            raise Exception(f"生成shortId失败: {short_id_output.stderr}")
        
        short_id = short_id_output.stdout.strip()
        
        return private_key, public_key, short_id
    except subprocess.TimeoutExpired:
        raise Exception("生成密钥超时")
    except Exception as e:
        raise Exception(f"生成密钥过程中出错: {e}")

# --- 核心逻辑重构 ---

def generate_all_configs(domain, uuid_str, public_key, private_key, short_id):
    """生成所有节点链接和客户端配置文件，并返回用于UI显示的文本。"""
    hostname = socket.gethostname()[:10]
    all_links = []
    
    # 生成VLESS Reality链接
    all_links.append(generate_vless_reality_link({
        "ps": f"VLESS-Reality-{hostname}",
        "uuid": uuid_str,
        "host": domain,
        "port": "443",
        "public_key": public_key,
        "sni": "www.amazon.com",  # 可更换为其他知名网站: www.apple.com, www.microsoft.com, www.google.com等
        "short_id": short_id
    }))
    
    ALL_NODES_FILE.write_text("\n".join(all_links) + "\n")

    list_output_text = f"""
✅ **VLESS Reality 服务已启动**
---
- **域名 (Domain):** `{domain}`
- **UUID:** `{uuid_str}`
- **公钥 (Public Key):** `{public_key}`
- **私钥 (Private Key):** `{private_key}`
- **Short ID:** `{short_id}`
- **SNI:** `www.amazon.com` (可自行更换)
---
**VLESS Reality 链接 (可复制):**
""" + "\n".join(all_links)
    LIST_FILE.write_text(list_output_text)
    
    # 生成sing-box客户端配置
    generate_singbox_config(domain, uuid_str, public_key, short_id)
    
    return list_output_text

def generate_singbox_config(domain, uuid_str, public_key, short_id):
    """生成sing-box客户端配置文件"""
    client_config = {
        "log": {
            "level": "info",
            "timestamp": True
        },
        "inbounds": [
            {
                "type": "socks",
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "listen_port": 1080,
                "sniff": True,
                "sniff_override_destination": True
            },
            {
                "type": "http",
                "tag": "http-in",
                "listen": "127.0.0.1",
                "listen_port": 1081
            }
        ],
        "outbounds": [
            {
                "type": "vless",
                "tag": "proxy",
                "server": domain,
                "server_port": 443,
                "uuid": uuid_str,
                "flow": "xtls-rprx-vision",
                "tls": {
                    "enabled": True,
                    "server_name": "www.amazon.com",
                    "utls": {
                        "enabled": True,
                        "fingerprint": "chrome"
                    },
                    "reality": {
                        "enabled": True,
                        "public_key": public_key,
                        "short_id": short_id
                    }
                }
            },
            {
                "type": "direct",
                "tag": "direct"
            },
            {
                "type": "block",
                "tag": "block"
            }
        ],
        "route": {
            "rules": [
                {
                    "geoip": [
                        "cn",
                        "private"
                    ],
                    "outbound": "direct"
                },
                {
                    "geosite": [
                        "cn"
                    ],
                    "outbound": "direct"
                }
            ]
        }
    }
    
    SINGBOX_CONFIG_FILE.write_text(json.dumps(client_config, indent=2))

def start_services(uuid_str, port_vm_ws, custom_domain, argo_token):
    """核心函数：根据Secrets中的配置，安装并启动VLESS Reality服务。"""
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
            
            # 下载并安装 sing-box
            if not singbox_path.exists():
                sb_version, sb_name_actual = "1.9.0-beta.11", f"sing-box-1.9.0-beta.11-linux-{arch}"
                tar_path = INSTALL_DIR / "sing-box.tar.gz"
                if not download_file(f"https://github.com/SagerNet/sing-box/releases/download/v{sb_version}/{sb_name_actual}.tar.gz", tar_path):
                    return False, "sing-box 下载失败。"
                
                import tarfile
                with tarfile.open(tar_path, "r:gz") as tar: 
                    tar.extractall(path=INSTALL_DIR)
                
                # 确保提取的目录存在
                extracted_dir = INSTALL_DIR / sb_name_actual
                if extracted_dir.exists():
                    # 移动 sing-box 可执行文件
                    extracted_singbox = extracted_dir / "sing-box"
                    if extracted_singbox.exists():
                        shutil.move(extracted_singbox, singbox_path)
                    # 删除提取的目录
                    shutil.rmtree(extracted_dir)
                
                # 删除压缩包
                tar_path.unlink(missing_ok=True)
                
                # 设置执行权限
                os.chmod(singbox_path, 0o755)

            # 下载并安装 cloudflared
            cloudflared_path = INSTALL_DIR / "cloudflared"
            if not cloudflared_path.exists():
                cf_arch = "amd64" if arch == "amd64" else "arm"
                if not download_file(f"https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-{cf_arch}", cloudflared_path):
                    return False, "cloudflared 下载失败。"
                os.chmod(cloudflared_path, 0o755)

        with st.spinner("正在生成Reality密钥..."):
            # 生成Reality所需的密钥和shortId
            private_key, public_key, short_id = generate_reality_keys(singbox_path)

        with st.spinner("正在根据您的配置启动VLESS Reality服务..."):
            # 生成VLESS Reality服务器配置
            sb_config = {
                "log": {
                    "level": "info",
                    "timestamp": True
                },
                "inbounds": [
                    {
                        "type": "vless",
                        "tag": "vless-in",
                        "listen": "127.0.0.1",
                        "listen_port": port_vm_ws,
                        "sniff": True,
                        "sniff_override_destination": True,
                        "users": [
                            {
                                "uuid": uuid_str,
                                "flow": "xtls-rprx-vision"
                            }
                        ],
                        "tls": {
                            "enabled": True,
                            "server_name": "www.amazon.com",
                            "reality": {
                                "enabled": True,
                                "handshake": {
                                    "server": "www.amazon.com",
                                    "server_port": 443
                                },
                                "private_key": private_key,
                                "short_id": [short_id]
                            }
                        }
                    }
                ],
                "outbounds": [
                    {
                        "type": "direct"
                    }
                ]
            }
            
            (INSTALL_DIR / "sb.json").write_text(json.dumps(sb_config, indent=2))
            
            with open(SB_LOG_FILE, "w") as sb_log:
                sb_process = subprocess.Popen([str(singbox_path), 'run', '-c', 'sb.json'], 
                                             cwd=INSTALL_DIR, stdout=sb_log, stderr=subprocess.STDOUT)
            SB_PID_FILE.write_text(str(sb_process.pid))
            
            cf_cmd = [str(cloudflared_path), 'tunnel', '--no-autoupdate', 'run', '--token', argo_token] if argo_token else [str(cloudflared_path), 'tunnel', '--no-autoupdate', '--url', f'http://localhost:{port_vm_ws}', '--protocol', 'http2']
            with open(LOG_FILE, "w") as cf_log:
                cf_process = subprocess.Popen(cf_cmd, cwd=INSTALL_DIR, stdout=cf_log, stderr=subprocess.STDOUT)
            ARGO_PID_FILE.write_text(str(cf_process.pid))

        with st.spinner("正在获取隧道域名并生成节点信息..."):
            time.sleep(5)
            final_domain = custom_domain or (get_tunnel_domain() if not argo_token else None)
            if not final_domain:
                return False, "未能确定隧道域名。请检查日志 (`.agsb/argo.log`)。"

        links_output = generate_all_configs(final_domain, uuid_str, public_key, private_key, short_id)
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

# --- UI 渲染函数 (已大幅简化) ---

def render_main_ui(config):
    """渲染主控制面板。"""
    st.set_page_config(page_title="部署工具", layout="wide")
    st.header("⚙️ VLESS Reality 服务管理面板")

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
    if c1.button("🚀 启动/重启 VLESS Reality 服务", type="primary", use_container_width=True):
        success, message = start_services(config["uuid_str"], config["port_vm_ws"], config["custom_domain"], config["argo_token"])
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
        
        # 提供客户端配置文件下载
        if SINGBOX_CONFIG_FILE.exists():
            with open(SINGBOX_CONFIG_FILE, "r") as f:
                config_content = f.read()
            st.download_button(
                label="📥 下载 Sing-Box 客户端配置",
                data=config_content,
                file_name="singbox_client_config.json",
                mime="application/json",
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
