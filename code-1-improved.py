#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import json
import uuid as uuidlib
import shutil
import socket
import random
import platform
import subprocess
from pathlib import Path
import urllib.request
import streamlit as st

# ========== 常量 ==========
INSTALL_DIR = Path.home() / ".hy2"
BIN_PATH = INSTALL_DIR / "hysteria2"
SERVER_CFG = INSTALL_DIR / "server.yaml"
PID_FILE = INSTALL_DIR / "hy2.pid"
LOG_FILE = INSTALL_DIR / "hy2.log"
CERT_FILE = INSTALL_DIR / "cert.pem"
KEY_FILE = INSTALL_DIR / "key.pem"
CLIENT_CFG_FILE = INSTALL_DIR / "client.yaml"
LINKS_FILE = INSTALL_DIR / "links.txt"

DEFAULT_PORT = 8443  # 非 root 环境建议使用 8443，避免 443 需要特权
UA = {"User-Agent": "Mozilla/5.0"}

# ========== 工具函数 ==========

def http_get(url: str, timeout=8) -> bytes:
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()

def external_ip() -> str:
    # 优先 v4，失败再 v6
    try:
        return http_get("https://ipv4.icanhazip.com", 4).decode().strip()
    except Exception:
        pass
    try:
        return http_get("https://ipv6.icanhazip.com", 4).decode().strip()
    except Exception:
        return ""

def ensure_dir():
    INSTALL_DIR.mkdir(parents=True, exist_ok=True)

def arch_map() -> str:
    m = platform.machine().lower()
    if "x86_64" in m or "amd64" in m:
        return "amd64"
    if "aarch64" in m or "arm64" in m:
        return "arm64"
    return ""  # 未知架构

def download_hysteria() -> bool:
    arch = arch_map()
    if not arch:
        st.error(f"未识别的架构: {platform.machine()}")
        return False
    url = f"https://github.com/apernet/hysteria/releases/latest/download/hysteria-linux-{arch}"
    try:
        data = http_get(url, timeout=20)
        with open(BIN_PATH, "wb") as f:
            f.write(data)
        os.chmod(BIN_PATH, 0o755)
        return True
    except Exception as e:
        st.error(f"下载 Hysteria2 失败: {e}")
        return False

def check_hysteria():
    if not BIN_PATH.exists():
        return download_hysteria()
    return True

def openssl_available() -> bool:
    return shutil.which("openssl") is not None

def generate_self_signed_cert(common_name: str = "localhost") -> bool:
    try:
        # 生成 ECDSA 自签证书（有效期 10 年）
        subprocess.run(
            ["openssl", "ecparam", "-genkey", "-name", "prime256v1", "-out", str(KEY_FILE)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        subprocess.run(
            ["openssl", "req", "-new", "-x509", "-days", "3650",
             "-key", str(KEY_FILE), "-out", str(CERT_FILE),
             "-subj", f"/CN={common_name}"],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        return True
    except Exception as e:
        st.error(f"生成自签证书失败: {e}")
        return False

def write_server_config(port: int, password: str, cert_path: Path, key_path: Path):
    # Hysteria2 v2 服务端 YAML
    cfg = f"""listen: :{port}
tls:
  cert: {cert_path}
  key: {key_path}
auth:
  type: password
  password: "{password}"
# 可选：伪装网站反代（需你确认合法性与兼容性）
# masquerade:
#   type: proxy
#   proxy:
#     url: https://www.bing.com/
"""
    SERVER_CFG.write_text(cfg, encoding="utf-8")

def write_client_config(host: str, port: int, password: str, sni: str, insecure: bool = True):
    cfg = f"""# Hysteria2 客户端示例 (官方客户端)
server: {host}:{port}
auth: "{password}"
retry: 3
fast_open: true
tls:
  sni: {sni}
  insecure: {str(insecure).lower()}
# 本地代理转发
socks5:
  listen: 127.0.0.1:1080
http:
  listen: 127.0.0.1:8080
# 可选带宽提示（非硬限制）
# bandwidth:
#   up: 50 Mbps
#   down: 100 Mbps
# 可选：指定 ALPN
# alpn:
#   - h3
"""
    CLIENT_CFG_FILE.write_text(cfg, encoding="utf-8")

def gen_hy2_url(host: str, port: int, password: str, sni: str, name: str = "") -> str:
    tag = f"#{name}" if name else ""
    # 常见参数：alpn=h3，insecure=1（自签证书时）
    return f"hysteria2://{password}@{host}:{port}?sni={sni}&alpn=h3&insecure=1{tag}"

def process_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except Exception:
        return False

def stop_server():
    # 优雅终止 -> 强制
    if PID_FILE.exists():
        try:
            pid = int(PID_FILE.read_text().strip())
            try:
                os.kill(pid, 15)
                time.sleep(1)
            except Exception:
                pass
            try:
                os.kill(pid, 9)
            except Exception:
                pass
        except Exception:
            pass
        finally:
            PID_FILE.unlink(missing_ok=True)
    # 再兜底清理
    subprocess.run("pkill -TERM -f 'hysteria server -c'", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run("pkill -KILL -f 'hysteria server -c'", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def start_server():
    with open(LOG_FILE, "w") as log:
        p = subprocess.Popen([str(BIN_PATH), "server", "-c", str(SERVER_CFG)],
                             cwd=INSTALL_DIR, stdout=log, stderr=subprocess.STDOUT)
    PID_FILE.write_text(str(p.pid))

def ensure_port_available(port: int) -> bool:
    # 仅检查 TCP 绑定以粗略发现占用（hy2 用 UDP，但此处无法简便检测 UDP 占用）
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", port))
        s.close()
        return True
    except Exception:
        return False

# ========== UI ==========

def render_login(secret_key: str):
    st.set_page_config(page_title="Hysteria2 控制台", layout="centered")
    st.title("🔐 登录")
    token = st.text_input("输入访问口令（SECRET_KEY）", type="password")
    if st.button("登录", type="primary"):
        if token == secret_key:
            st.session_state.auth = True
            st.rerun()
        else:
            st.error("口令不正确")

def render_main():
    st.set_page_config(page_title="Hysteria2 控制台", layout="wide")
    st.title("⚙️ Hysteria2 一键部署面板")

    # 读取/初始化配置
    st.sidebar.header("运行设置")
    default_host = st.secrets.get("PUBLIC_HOST", "")  # 建议填入你的公网域名（强烈推荐）
    password = st.sidebar.text_input("连接密码（留空自动生成）", value=st.secrets.get("HY2_PASSWORD", ""))
    port = st.sidebar.number_input("服务端口（UDP）", min_value=1025, max_value=65535, value=int(st.secrets.get("HY2_PORT", DEFAULT_PORT)))
    public_host = st.sidebar.text_input("公网访问域名或 IP（推荐域名）", value=default_host)
    display_name = st.sidebar.text_input("节点名称后缀（可选）", value=socket.gethostname()[:10])

    st.sidebar.markdown("---")
    cert_mode = st.sidebar.radio("证书模式", ["自签证书（自用）", "上传证书（推荐）"])
    uploaded_cert = uploaded_key = None
    if cert_mode == "上传证书（推荐）":
        uploaded_cert = st.sidebar.file_uploader("上传证书 cert.pem", type=["pem", "crt"])
        uploaded_key = st.sidebar.file_uploader("上传私钥 key.pem", type=["pem", "key"])
        st.sidebar.info("请确保域名已解析到本机公网 IP，且证书与域名匹配。")

    st.markdown("---")

    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("🚀 启动/重启服务", type="primary", use_container_width=True):
            ensure_dir()
            # 校验 & 准备
            if not public_host:
                # 尝试自动探测
                auto_ip = external_ip()
                if auto_ip:
                    public_host = auto_ip
                    st.warning(f"未填写公网域名/IP，已自动检测为：{public_host}")
                else:
                    st.error("无法确定公网访问域名/IP，请手动填写。")
                    st.stop()

            if not ensure_port_available(port):
                st.error(f"端口 {port} 似乎被占用（或无权限绑定 <1024 端口）。请更换端口。")
                st.stop()

            with st.spinner("停止旧进程..."):
                stop_server()

            with st.spinner("检查/下载 Hysteria2..."):
                if not check_hysteria():
                    st.stop()

            # 证书处理
            if cert_mode == "上传证书（推荐）":
                if not (uploaded_cert and uploaded_key):
                    st.error("请同时上传 cert 与 key 文件。")
                    st.stop()
                CERT_FILE.write_bytes(uploaded_cert.read())
                KEY_FILE.write_bytes(uploaded_key.read())
            else:
                if not openssl_available():
                    st.error("系统缺少 openssl，无法生成自签证书。请改用“上传证书（推荐）”模式。")
                    st.stop()
                with st.spinner("生成自签证书..."):
                    if not generate_self_signed_cert(public_host):
                        st.stop()

            # 密码准备
            if not password:
                password = uuidlib.uuid4().hex

            # 写配置文件并启动
            write_server_config(port, password, CERT_FILE, KEY_FILE)
            with st.spinner("启动 Hysteria2 服务..."):
                start_server()
                time.sleep(1)

            # 生成客户端配置与订阅链接
            write_client_config(public_host, port, password, sni=public_host, insecure=(cert_mode == "自签证书（自用）"))
            hy2_url = gen_hy2_url(public_host, port, password, sni=public_host, name=display_name)
            LINKS_FILE.write_text(hy2_url + "\n", encoding="utf-8")

            st.success("服务已启动")
            st.session_state["hy2_url"] = hy2_url
            st.session_state["password"] = password
            st.rerun()

    with col2:
        if st.button("⏹️ 停止服务", use_container_width=True):
            with st.spinner("停止中..."):
                stop_server()
            st.success("已停止")
            st.rerun()

    with col3:
        if st.button("🧹 卸载清理", use_container_width=True):
            with st.spinner("清理中..."):
                stop_server()
                if INSTALL_DIR.exists():
                    shutil.rmtree(INSTALL_DIR)
            st.success("已卸载并清理全部运行文件")
            st.rerun()

    # 状态与输出
    st.markdown("---")
    running = False
    if PID_FILE.exists():
        try:
            pid = int(PID_FILE.read_text().strip())
            running = process_running(pid)
        except Exception:
            running = False

    st.subheader("运行状态")
    if running:
        st.success(f"运行中 (PID: {PID_FILE.read_text().strip()})")
    else:
        st.warning("未在运行")

    st.subheader("订阅链接与客户端配置")
    hy2_url = st.session_state.get("hy2_url", "")
    if hy2_url:
        st.code(hy2_url, language="text")
        st.download_button("下载 links.txt", LINKS_FILE.read_bytes(), file_name="links.txt")
    if CLIENT_CFG_FILE.exists():
        st.code(CLIENT_CFG_FILE.read_text(), language="yaml")
        st.download_button("下载 client.yaml", CLIENT_CFG_FILE.read_bytes(), file_name="client.yaml")

    st.subheader("日志")
    log_text = LOG_FILE.read_text() if LOG_FILE.exists() else "暂无日志"
    st.code(log_text[-8000:], language="bash")

    st.info("提示：请在云厂商安全组与本机防火墙中放行所选 UDP 端口（默认 8443）。")

def main():
    st.session_state.setdefault("auth", False)
    # 读取 SECRET_KEY（可选）
    secret_key = st.secrets.get("SECRET_KEY", "")
    if secret_key:
        if not st.session_state["auth"]:
            render_login(secret_key)
            return
    render_main()

if __name__ == "__main__":
    main()
