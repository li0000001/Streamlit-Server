#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import random
import time
import shutil
import re
import base64
import socket
import subprocess
import platform
from datetime import datetime
import uuid
from pathlib import Path
import urllib.request
import streamlit as st

# --- 全局常量配置 ---
INSTALL_DIR = Path.home() / ".agsb"
CONFIG_FILE = INSTALL_DIR / "config.json"
SECRETS_FILE = INSTALL_DIR / "secrets.json"
SB_PID_FILE = INSTALL_DIR / "sbpid.log"
ARGO_PID_FILE = INSTALL_DIR / "sbargopid.log"
LIST_FILE = INSTALL_DIR / "list.txt"
LOG_FILE = INSTALL_DIR / "argo.log"
SB_LOG_FILE = INSTALL_DIR / "sb.log"
SINGBOX_CONFIG_FILE = INSTALL_DIR / "singbox_client_config.json"
ALL_NODES_FILE = INSTALL_DIR / "allnodes.txt"

# --- 辅助函数 ---

def download_file(url, target_path):
    """下载文件并保存到指定路径。"""
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as response, open(target_path, 'wb') as out_file:
            shutil.copyfileobj(response, out_file)
        return True
    except Exception as e:
        st.error(f"下载失败: {url}, 错误: {e}")
        return False

def generate_vmess_link(config):
    """根据配置字典生成Vmess链接。"""
    vmess_obj = {
        "v": "2", "ps": config.get("ps"), "add": config.get("add"), 
        "port": str(config.get("port")), "id": config.get("id"), "aid": "0", 
        "scy": "auto", "net": "ws", "type": "none", "host": config.get("host"), 
        "path": "/", "tls": "tls", "sni": config.get("sni")
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
    """停止 sing-box 和 cloudflared 进程。"""
    for pid_file in [SB_PID_FILE, ARGO_PID_FILE]:
        if pid_file.exists():
            try:
                pid = int(pid_file.read_text().strip())
                os.kill(pid, 9)
            except (ValueError, ProcessLookupError, FileNotFoundError):
                pass
            finally:
                pid_file.unlink(missing_ok=True)
    # 作为后备，强制杀死残留进程
    subprocess.run("pkill -9 -f 'sing-box run'", shell=True, capture_output=True)
    subprocess.run("pkill -9 -f 'cloudflared tunnel'", shell=True, capture_output=True)

def generate_all_configs(domain, uuid_str, port_vm_ws):
    """生成所有节点链接和客户端配置文件。"""
    hostname = socket.gethostname()[:10]
    all_links = []
    
    # 生成优选IP节点
    cf_ips_tls = {"104.16.0.0": "443", "104.17.0.0": "8443", "104.18.0.0": "2053", "104.19.0.0": "2083", "104.20.0.0": "2087"}
    for ip, port in cf_ips_tls.items():
        all_links.append(generate_vmess_link({"ps": f"VMWS-TLS-{hostname}-{ip.split('.')[2]}-{port}", "add": ip, "port": port, "id": uuid_str, "host": domain, "sni": domain}))
    
    # 生成域名直连节点
    all_links.append(generate_vmess_link({"ps": f"VMWS-TLS-Direct-{hostname}", "add": domain, "port": "443", "id": uuid_str, "host": domain, "sni": domain}))

    ALL_NODES_FILE.write_text("\n".join(all_links) + "\n")
    
    # 生成用于界面显示的文本
    list_output = [
        "✅ **服务启动成功!**\n---",
        f"**域名 (Domain):** `{domain}`",
        f"**UUID:** `{uuid_str}`",
        f"**本地端口:** `{port_vm_ws}`",
        "**WebSocket路径:** `/`\n---",
        "**Vmess 链接 (可复制):**"
    ] + all_links
    LIST_FILE.write_text("\n".join([re.sub(r'[`*]', '', line) for line in list_output]))

    # --- 生成 sing-box 客户端配置 ---
    outbounds, node_tags = [], []
    # 优选IP节点
    for link in all_links[:-1]:
        config = json.loads(base64.b64decode(link.replace("vmess://", "") + "==").decode())
        node_name = config['ps']
        node_tags.append(node_name)
        outbounds.append({"type": "vmess", "tag": node_name, "server": config['add'], "server_port": int(config['port']), "uuid": uuid_str, "security": "auto", "alter_id": 0, "transport": {"type": "ws", "path": "/", "headers": {"Host": domain}}, "tls": {"enabled": True, "server_name": domain, "insecure": False}})
    # 直连节点
    direct_config = json.loads(base64.b64decode(all_links[-1].replace("vmess://", "") + "==").decode())
    direct_node_name = direct_config['ps']
    node_tags.append(direct_node_name)
    outbounds.append({"type": "vmess", "tag": direct_node_name, "server": domain, "server_port": 443, "uuid": uuid_str, "security": "auto", "alter_id": 0, "transport": {"type": "ws", "path": "/", "headers": {"Host": domain}}, "tls": {"enabled": True, "server_name": domain, "insecure": False}})
    
    # 组装完整配置
    outbounds.insert(0, {"type": "selector", "tag": "节点选择", "outbounds": node_tags, "default": direct_node_name})
    outbounds.extend([{"type": "direct", "tag": "direct"}, {"type": "block", "tag": "block"}])
    random_socks_port = random.randint(2000, 50000)
    client_config = {
        "log": {"level": "info", "timestamp": True},
        "dns": {"servers": [{"address": "8.8.8.8"}, {"address": "1.1.1.1"}]},
        "inbounds": [
            {"type": "tun", "tag": "tun-in", "interface_name": "tun0", "inet4_address": "172.19.0.1/30", "auto_route": True, "strict_route": True},
            {"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": random_socks_port},
            {"type": "http", "tag": "http-in", "listen": "127.0.0.1", "listen_port": random_socks_port + 1}
        ],
        "outbounds": outbounds,
        "route": {"rules": [{"protocol": "dns", "outbound": "direct"}], "final": "节点选择"}
    }
    SINGBOX_CONFIG_FILE.write_text(json.dumps(client_config, indent=2))
    
    return "\n".join(list_output)

def apply_config_and_restart(uuid_str, port_vm_ws, custom_domain, argo_token):
    """核心函数：保存配置、安装依赖并启动服务。"""
    with st.spinner("正在停止现有服务..."):
        stop_services()
    
    try:
        INSTALL_DIR.mkdir(parents=True, exist_ok=True)
        
        # 保存配置
        config = {
            "uuid_str": uuid_str or str(uuid.uuid4()),
            "port_vm_ws": port_vm_ws or random.randint(10000, 65535),
            "custom_domain_agn": custom_domain,
            "argo_token": argo_token
        }
        CONFIG_FILE.write_text(json.dumps(config, indent=2))
        
        # 再次读取，确保使用的是保存后（可能已自动生成）的值
        uuid_str, port_vm_ws = config["uuid_str"], config["port_vm_ws"]

        # 检查并安装依赖
        with st.spinner("正在检查并安装依赖 (sing-box, cloudflared)..."):
            arch = "amd64" if "x86_64" in platform.machine().lower() else "arm64"
            
            singbox_path = INSTALL_DIR / "sing-box"
            if not singbox_path.exists():
                sb_version, sb_name_actual = "1.9.0-beta.11", f"sing-box-1.9.0-beta.11-linux-{arch}"
                tar_path = INSTALL_DIR / "sing-box.tar.gz"
                if not download_file(f"https://github.com/SagerNet/sing-box/releases/download/v{sb_version}/{sb_name_actual}.tar.gz", tar_path):
                    return False, "sing-box 下载失败。"
                import tarfile
                with tarfile.open(tar_path, "r:gz") as tar: tar.extractall(path=INSTALL_DIR)
                shutil.move(INSTALL_DIR / sb_name_actual / "sing-box", singbox_path)
                shutil.rmtree(INSTALL_DIR / sb_name_actual); tar_path.unlink(); os.chmod(singbox_path, 0o755)

            cloudflared_path = INSTALL_DIR / "cloudflared"
            if not cloudflared_path.exists():
                cf_arch = "amd64" if arch == "amd64" else "arm"
                if not download_file(f"https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-{cf_arch}", cloudflared_path):
                    return False, "cloudflared 下载失败。"
                os.chmod(cloudflared_path, 0o755)

        # 启动服务
        with st.spinner("正在启动服务..."):
            # 创建 sing-box 服务器配置文件
            sb_config = {"log": {"level": "info"}, "inbounds": [{"type": "vmess", "tag": "vmess-in", "listen": "127.0.0.1", "listen_port": port_vm_ws, "sniff": True, "users": [{"uuid": uuid_str, "alterId": 0}], "transport": {"type": "ws", "path": "/"}}], "outbounds": [{"type": "direct"}]}
            (INSTALL_DIR / "sb.json").write_text(json.dumps(sb_config, indent=2))
            
            # 启动 sing-box
            with open(SB_LOG_FILE, "w") as sb_log:
                sb_process = subprocess.Popen([str(singbox_path), 'run', '-c', 'sb.json'], cwd=INSTALL_DIR, stdout=sb_log, stderr=subprocess.STDOUT)
            SB_PID_FILE.write_text(str(sb_process.pid))
            
            # 启动 cloudflared
            if argo_token:
                cf_cmd = [str(cloudflared_path), 'tunnel', '--no-autoupdate', 'run', '--token', argo_token]
            else:
                cf_cmd = [str(cloudflared_path), 'tunnel', '--no-autoupdate', '--url', f'http://localhost:{port_vm_ws}', '--protocol', 'http2']
            with open(LOG_FILE, "w") as cf_log:
                cf_process = subprocess.Popen(cf_cmd, cwd=INSTALL_DIR, stdout=cf_log, stderr=subprocess.STDOUT)
            ARGO_PID_FILE.write_text(str(cf_process.pid))

        with st.spinner("正在获取隧道域名并生成节点信息..."):
            time.sleep(5) # 等待 cloudflared 初始化
            final_domain = custom_domain or (get_tunnel_domain() if not argo_token else None)
            if not final_domain:
                return False, "未能确定隧道域名。请检查日志 (`.agsb/argo.log`)。"

        links_output = generate_all_configs(final_domain, uuid_str, port_vm_ws)
        return True, links_output
    
    except Exception as e:
        return False, f"处理过程中发生意外错误: {e}"

def uninstall_services():
    """卸载服务，清理所有文件。"""
    stop_services()
    if INSTALL_DIR.exists():
        shutil.rmtree(INSTALL_DIR)
    st.success("✅ 卸载完成。所有相关文件和进程已清除。")
    st.session_state.clear() # 清理会话状态以回到初始设置

# --- UI 渲染函数 ---

def render_password_setup_ui():
    """渲染首次运行的密码设置界面。"""
    st.set_page_config(page_title="首次设置", layout="centered")
    st.title("🔐 首次运行 - 请设置访问密码")
    st.info("此密码用于访问后台管理面板。请务必牢记！")
    with st.form("password_setup_form"):
        secret_key_in = st.text_input("设置主访问密码", type="password")
        secret_key_confirm = st.text_input("确认主访问密码", type="password")
        submitted = st.form_submit_button("保存密码并继续")
        if submitted:
            if not secret_key_in:
                st.error("密码不能为空！")
            elif secret_key_in != secret_key_confirm:
                st.error("两次输入的密码不匹配！")
            else:
                INSTALL_DIR.mkdir(parents=True, exist_ok=True)
                SECRETS_FILE.write_text(json.dumps({"secret_key": secret_key_in}))
                st.success("密码已保存！页面将自动刷新...")
                time.sleep(2)
                st.rerun()

def render_main_ui():
    """渲染主控制面板。"""
    st.set_page_config(page_title="部署工具", layout="wide")
    st.header("⚙️ 服务配置与管理")

    # 加载现有配置
    if CONFIG_FILE.exists():
        config = json.loads(CONFIG_FILE.read_text())
    else:
        config = {}

    st.subheader("配置参数")
    st.info("修改下方任一参数后，点击“保存并重启服务”按钮即可生效。留空则使用默认或随机值。")

    # 使用列来布局
    col1, col2 = st.columns(2)
    with col1:
        uuid_str_in = st.text_input("UUID", value=config.get("uuid_str", ""), help="推荐留空，程序会自动生成一个标准的UUID。")
        custom_domain_in = st.text_input("自定义域名 (可选)", value=config.get("custom_domain_agn", ""), help="如果您有自己的域名并已在Cloudflare托管，可在此处填写。")
    with col2:
        port_vm_ws_in = st.number_input("本地端口", min_value=0, max_value=65535, value=config.get("port_vm_ws", 0), help="0代表随机选择一个10000到65535之间的端口。")
        argo_token_in = st.text_input("Argo Tunnel Token (可选)", value=config.get("argo_token", ""), type="password", help="使用自定义域名或固定子域名时需要填写对应的隧道Token。")

    st.markdown("---")
    st.subheader("控制操作")
    
    # 操作按钮
    c1, c2, c3 = st.columns(3)
    if c1.button("💾 保存并重启服务", type="primary", use_container_width=True):
        success, message = apply_config_and_restart(uuid_str_in, port_vm_ws_in, custom_domain_in, argo_token_in)
        if success:
            st.success("服务已成功启动！节点信息已更新。")
            st.session_state.output = message
        else:
            st.error(f"操作失败: {message}")
            st.session_state.output = message
    
    if c2.button("👀 查看节点信息", use_container_width=True):
        st.session_state.viewing_nodes = True
        st.rerun()

    if c3.button("❌ 永久卸载服务", use_container_width=True):
        with st.spinner("正在执行卸载..."):
            uninstall_services()
        st.rerun()
    
    # 显示上次操作的输出
    if 'output' in st.session_state and st.session_state.output:
        st.code(st.session_state.output)
        st.session_state.output = ""

def render_node_info_page():
    """渲染节点信息展示页面。"""
    st.set_page_config(page_title="节点信息", layout="wide")
    st.title("🚀 节点信息详情")
    st.info("请及时复制所需信息。离开此页面后将返回主面板。")

    # 显示节点信息
    if LIST_FILE.exists():
        st.markdown(LIST_FILE.read_text(), unsafe_allow_html=True)
    else:
        st.warning("节点信息文件不存在，可能服务还未成功启动。请返回主面板重启服务。")

    st.markdown("---")
    
    # 配置文件下载
    col1, col2 = st.columns(2)
    with col1:
        with st.expander("📥 下载 sing-box 客户端配置文件 (推荐)", expanded=True):
            if SINGBOX_CONFIG_FILE.exists():
                config_content = SINGBOX_CONFIG_FILE.read_text()
                st.code(config_content, language="json")
                st.download_button(label="下载 config.json", data=config_content.encode('utf-8'), file_name="config.json", mime="application/json")
            else:
                st.warning("客户端配置文件不存在。")
    with col2:
        with st.expander("📋 复制 Vmess 节点链接 (兼容其他客户端)", expanded=True):
            if ALL_NODES_FILE.exists():
                st.code(ALL_NODES_FILE.read_text(), language="text")
            else:
                st.warning("Vmess链接文件不存在。")

    st.markdown("---")
    if st.button("返回主面板 ↩️", type="primary"):
        st.session_state.viewing_nodes = False
        st.rerun()

def render_login_ui(secret_key):
    """渲染伪装的登录界面。"""
    st.set_page_config(page_title="天气查询", layout="centered")
    st.title("🌦️ 实时天气查询")
    st.write("一个简单的天气查询工具。")
    city = st.text_input("请输入城市名或秘密口令：", "Beijing")
    if st.button("查询天气"):
        if city == secret_key:
            st.session_state.authenticated = True
            st.rerun()
        else:
            with st.spinner(f"正在查询 {city} 的天气..."):
                time.sleep(1)
                st.error(random.choice(["查询失败", "API密钥过期", "网络超时"]))
    st.markdown("---")
    st.info("这是一个开源项目。")

def main():
    """主应用逻辑。"""
    # 初始化会话状态
    st.session_state.setdefault('authenticated', False)
    st.session_state.setdefault('viewing_nodes', False)
    st.session_state.setdefault('output', "")
    
    # 检查密码文件是否存在
    if not SECRETS_FILE.exists():
        render_password_setup_ui()
        return

    # 读取密码
    try:
        secrets = json.loads(SECRETS_FILE.read_text())
        secret_key = secrets.get("secret_key")
        if not secret_key:
            st.error("密码文件损坏或内容为空，请删除 `.agsb/secrets.json` 后刷新页面重置。")
            return
    except Exception as e:
        st.error(f"加载密码文件失败: {e}。请删除 `.agsb/secrets.json` 后刷新页面重置。")
        return
    
    # 根据认证和页面状态选择渲染哪个UI
    if st.session_state.authenticated:
        if st.session_state.viewing_nodes:
            render_node_info_page()
        else:
            render_main_ui()
    else:
        render_login_ui(secret_key)

if __name__ == "__main__":
    main()