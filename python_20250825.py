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
        return "1.10.1"

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
    """生成Vmess链接 - 修复v2rayN兼容性问题。"""
    vmess_obj = {
        "v": "2",
        "ps": config.get("ps", ""),
        "add": config.get("add", ""),
        "port": config.get("port", "443"),
        "id": config.get("id", ""),
        "aid": "0",
        "scy": "auto",
        "net": "ws",
        "type": "none",
        "host": config.get("host", ""),
        "path": config.get("path", "/"),
        "tls": "tls",
        "sni": config.get("sni", ""),
        "alpn": "",
        "fp": ""
    }
    vmess_str = json.dumps(vmess_obj, separators=(',', ':'), ensure_ascii=False)
    vmess_base64 = base64.b64encode(vmess_str.encode('utf-8')).decode('utf-8')
    return f"vmess://{vmess_base64}"

def get_tunnel_domain():
    """从argo日志中获取临时隧道域名。"""
    max_attempts = 30  # 增加等待时间
    for i in range(max_attempts):
        if LOG_FILE.exists():
            try:
                log_content = LOG_FILE.read_text()
                match = re.search(r'https://([a-zA-Z0-9.-]+\.trycloudflare\.com)', log_content)
                if match:
                    return match.group(1)
            except Exception:
                pass
        time.sleep(2)
    return None

def stop_services():
    """停止所有相关服务进程。"""
    for pid_file in [SB_PID_FILE, ARGO_PID_FILE]:
        if pid_file.exists():
            try:
                pid = int(pid_file.read_text().strip())
                os.kill(pid, 9)
            except (ValueError, ProcessLookupError, FileNotFoundError):
                pass
            finally:
                pid_file.unlink(missing_ok=True)
    subprocess.run("pkill -9 -f 'sing-box run'", shell=True, capture_output=True)
    subprocess.run("pkill -9 -f 'cloudflared tunnel'", shell=True, capture_output=True)

# --- 核心逻辑 ---

def generate_all_configs(domain, uuid_str, port_vm_ws):
    """生成所有节点链接和客户端配置文件。"""
    hostname = socket.gethostname()[:10]
    all_links = []
    
    # 使用更可靠的CF IP
    cf_ips_tls = {
        "172.67.0.1": "443",
        "104.21.0.1": "443",
        "162.159.0.1": "443",
        "172.64.0.1": "2053",
        "188.114.96.1": "2083",
        "188.114.97.1": "2087",
        "188.114.98.1": "8443"
    }
    
    # 生成CF IP节点
    for ip, port in cf_ips_tls.items():
        config = {
            "ps": f"CF-{hostname}-{ip.replace('.', '-')}-{port}",
            "add": ip,
            "port": port,
            "id": uuid_str,
            "host": domain,
            "sni": domain,
            "path": "/"
        }
        all_links.append(generate_vmess_link(config))
    
    # 生成直连节点
    direct_config = {
        "ps": f"Direct-{hostname}",
        "add": domain,
        "port": "443",
        "id": uuid_str,
        "host": domain,
        "sni": domain,
        "path": "/"
    }
    all_links.append(generate_vmess_link(direct_config))
    
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

"""
    for link in all_links:
        list_output_text += f"{link}\n\n"
    
    LIST_FILE.write_text(list_output_text)
    return list_output_text

def start_services(uuid_str, port_vm_ws, custom_domain, argo_token):
    """核心函数：根据配置启动服务。"""
    with st.spinner("正在停止任何可能残留的旧服务..."):
        stop_services()
    
    try:
        INSTALL_DIR.mkdir(parents=True, exist_ok=True)
        
        # 补全可能为空的配置
        uuid_str = uuid_str or str(uuid.uuid4())
        port_vm_ws = port_vm_ws or random.randint(10000, 65535)

        with st.spinner("正在检查并安装依赖..."):
            arch = "amd64" if "x86_64" in platform.machine().lower() else "arm64"
            singbox_path = INSTALL_DIR / "sing-box"
            
            # 下载sing-box
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

            # 下载cloudflared
            cloudflared_path = INSTALL_DIR / "cloudflared"
            if not cloudflared_path.exists():
                cf_arch = "amd64" if arch == "amd64" else "arm"
                if not download_file(
                    f"https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-{cf_arch}",
                    cloudflared_path
                ):
                    return False, "cloudflared 下载失败。"
                os.chmod(cloudflared_path, 0o755)

        with st.spinner("正在启动服务..."):
            # 简化的sing-box配置，确保兼容性
            sb_config = {
                "log": {
                    "level": "info"
                },
                "inbounds": [
                    {
                        "type": "vmess",
                        "tag": "vmess-in",
                        "listen": "127.0.0.1",
                        "listen_port": port_vm_ws,
                        "users": [
                            {
                                "uuid": uuid_str,
                                "alterId": 0
                            }
                        ],
                        "transport": {
                            "type": "ws",
                            "path": "/",
                            "headers": {}
                        }
                    }
                ],
                "outbounds": [
                    {
                        "type": "direct",
                        "tag": "direct"
                    }
                ]
            }
            
            config_path = INSTALL_DIR / "sb.json"
            config_path.write_text(json.dumps(sb_config, indent=2))
            
            # 启动sing-box
            with open(SB_LOG_FILE, "w") as sb_log:
                sb_process = subprocess.Popen(
                    [str(singbox_path), 'run', '-c', str(config_path)],
                    cwd=INSTALL_DIR,
                    stdout=sb_log,
                    stderr=subprocess.STDOUT
                )
            SB_PID_FILE.write_text(str(sb_process.pid))
            
            # 等待sing-box启动
            time.sleep(3)
            
            # 检查sing-box是否成功启动
            if sb_process.poll() is not None:
                log_content = SB_LOG_FILE.read_text() if SB_LOG_FILE.exists() else "无日志"
                return False, f"sing-box启动失败。日志：\n{log_content}"
            
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

        with st.spinner("正在获取隧道域名..."):
            time.sleep(5)
            
            if custom_domain:
                final_domain = custom_domain
            elif not argo_token:
                final_domain = get_tunnel_domain()
                if not final_domain:
                    # 读取日志以获取更多信息
                    log_content = LOG_FILE.read_text() if LOG_FILE.exists() else "无日志"
                    return False, f"未能获取隧道域名。Cloudflared日志：\n{log_content}"
            else:
                # 使用token时，需要从配置中获取域名
                return False, "使用Argo Token时，必须提供自定义域名。"

        links_output = generate_all_configs(final_domain, uuid_str, port_vm_ws)
        return True, links_output
    
    except Exception as e:
        import traceback
        error_detail = traceback.format_exc()
        return False, f"处理过程中发生错误:\n{error_detail}"

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
    st.info("配置已从您的 `secrets.toml` 文件中加载。")
    
    config_display = {
        "UUID": config["uuid_str"] or "将自动生成",
        "本地端口": config["port_vm_ws"] or "将随机选择",
        "自定义域名": config["custom_domain"] or "将使用Cloudflare临时域名",
        "Argo Token": "已提供" if config["argo_token"] else "未提供"
    }
    st.json(config_display)

    st.markdown("---")
    st.subheader("控制操作")
    
    c1, c2, c3 = st.columns([2, 2, 1])
    
    if c1.button("🚀 启动/重启服务", type="primary", use_container_width=True):
        success, message = start_services(
            config["uuid_str"],
            config["port_vm_ws"],
            config["custom_domain"],
            config["argo_token"]
        )
        if success:
            st.session_state.output = message
            st.success("服务启动成功！")
        else:
            st.error(f"服务启动失败")
            st.session_state.output = f"错误信息：\n{message}"
            st.rerun()

    if c2.button("❌ 永久卸载服务", use_container_width=True):
        with st.spinner("正在执行卸载..."):
            uninstall_services()
        st.rerun()
    
    if c3.button("🔄 刷新", use_container_width=True):
        st.rerun()
    
    # 显示节点信息区域
    if 'output' in st.session_state and st.session_state.output:
        st.markdown("---")
        st.subheader("📋 节点信息")
        
        # 创建文本区域显示输出
        st.text_area("节点链接（点击复制）", st.session_state.output, height=400)
        
        # 添加使用说明
        with st.expander("📖 使用说明", expanded=True):
            st.markdown("""
            ### v2rayN 使用步骤：
            
            1. **导入节点**
               - 复制上面任意一个 `vmess://` 开头的链接
               - 打开 v2rayN，点击主界面的 "服务器" → "从剪贴板导入批量URL"
               - 或者按 `Ctrl+V` 快速导入
            
            2. **选择节点**
               - 在服务器列表中找到刚导入的节点
               - 右键点击节点，选择 "设为活动服务器"
               - 或者双击节点激活
            
            3. **启用代理**
               - 确保 v2rayN 主界面底部显示 "已启动"
               - 系统代理模式选择 "自动配置系统代理"
            
            ### 故障排查：
            
            - **连接显示 -1**：
              - 检查服务是否正在运行（查看上方状态）
              - 尝试使用不同的节点（不同IP）
              - 确保系统时间准确
            
            - **YouTube 无法播放**：
              - 在 v2rayN 设置中启用 "Mux多路复用"
              - 尝试切换到 CF 开头的节点
              - 清除浏览器缓存和Cookie
            
            - **速度慢**：
              - 选择延迟较低的节点
              - 避免使用 Direct 直连节点
              - 使用 CF 优选IP节点
            """)
        
        # 显示服务状态
        st.markdown("---")
        st.subheader("🔍 服务状态")
        
        col1, col2 = st.columns(2)
        
        with col1:
            if SB_PID_FILE.exists():
                st.success("✅ Sing-box 运行中")
                if st.button("查看 Sing-box 日志"):
                    if SB_LOG_FILE.exists():
                        log_content = SB_LOG_FILE.read_text()
                        st.code(log_content[-1000:])  # 显示最后1000字符
            else:
                st.error("❌ Sing-box 未运行")
        
        with col2:
            if ARGO_PID_FILE.exists():
                st.success("✅ Cloudflared 运行中")
                if st.button("查看 Cloudflared 日志"):
                    if LOG_FILE.exists():
                        log_content = LOG_FILE.read_text()
                        st.code(log_content[-1000:])  # 显示最后1000字符
            else:
                st.error("❌ Cloudflared 未运行")

def render_login_ui(secret_key):
    """渲染伪装的登录界面。"""
    st.set_page_config(page_title="天气查询", layout="centered")
    
    # 自定义CSS样式
    st.markdown("""
    <style>
    .main {
        padding-top: 2rem;
    }
    .stButton>button {
        background-color: #4CAF50;
        color: white;
        border-radius: 5px;
    }
    </style>
    """, unsafe_allow_html=True)
    
    st.title("🌦️ 实时天气查询系统")
    st.markdown("---")
    
    # 添加天气背景装饰
    st.markdown("""
    <div style='background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                padding: 20px; border-radius: 10px; margin-bottom: 20px;'>
        <h3 style='color: white; text-align: center; margin: 0;'>
            为您提供全球城市的实时天气信息
        </h3>
    </div>
    """, unsafe_allow_html=True)
    
    # 输入区域
    col1, col2, col3 = st.columns([1, 3, 1])
    with col2:
        city = st.text_input(
            "🏙️ 请输入城市名称",
            placeholder="例如: Beijing, Shanghai, New York...",
            key="city_input"
        )
        
        col_a, col_b, col_c = st.columns([1, 2, 1])
        with col_b:
            query_button = st.button("🔍 查询天气", use_container_width=True)
    
    # 天气图标展示
    st.markdown("""
    <div style='text-align: center; padding: 30px 0;'>
        <span style='font-size: 60px;'>☀️</span>
        <span style='font-size: 50px;'>🌤️</span>
        <span style='font-size: 60px;'>⛅</span>
        <span style='font-size: 50px;'>🌧️</span>
        <span style='font-size: 60px;'>❄️</span>
    </div>
    """, unsafe_allow_html=True)
    
    if query_button and city:
        if city == secret_key:
            st.session_state.authenticated = True
            st.rerun()
        else:
            with st.spinner(f"正在查询 {city} 的天气信息..."):
                time.sleep(1.5)
            
            # 显示假的天气信息
            st.error(f"⚠️ 无法获取 {city} 的天气数据")
            
            # 显示随机天气建议
            suggestions = [
                "请检查城市名称拼写是否正确",
                "尝试使用英文城市名",
                "确保网络连接正常",
                "该城市可能暂不支持查询"
            ]
            st.info(f"💡 提示：{random.choice(suggestions)}")
            
            # 显示支持的城市列表
            with st.expander("查看支持的城市列表"):
                st.markdown("""
                **热门城市：**
                - 中国：Beijing, Shanghai, Guangzhou, Shenzhen
                - 美国：New York, Los Angeles, Chicago
                - 欧洲：London, Paris, Berlin, Rome
                - 亚洲：Tokyo, Seoul, Singapore, Bangkok
                """)
    
    # 页脚
    st.markdown("---")
    st.caption("© 2024 Weather Query System. All rights reserved.")

def main():
    """主应用逻辑。"""
    # 初始化session state
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'output' not in st.session_state:
        st.session_state.output = ""
    
    # 从 Streamlit Secrets 读取配置
    try:
        # 读取必需的SECRET_KEY
        secret_key = st.secrets["SECRET_KEY"]
        
        # 读取其他可选配置
        config = {
            "uuid_str": st.secrets.get("UUID_STR", ""),
            "port_vm_ws": 0,
            "custom_domain": st.secrets.get("CUSTOM_DOMAIN", ""),
            "argo_token": st.secrets.get("ARGO_TOKEN", "")
        }
        
        # 处理端口配置
        port_config = st.secrets.get("PORT_VM_WS", "")
        if port_config:
            try:
                config["port_vm_ws"] = int(port_config)
            except ValueError:
                config["port_vm_ws"] = 0
                
    except KeyError as e:
        st.error(f"❌ 错误：未找到必需的配置项 '{e}'")
        st.markdown("""
        ### 📝 配置说明
        
        请在 Streamlit Cloud 的 Settings → Secrets 中添加以下配置：
        
        ```toml
        # 必需配置
        SECRET_KEY = "your-secret-password"
        
        # 可选配置
        UUID_STR = ""          # 留空将自动生成
        PORT_VM_WS = ""        # 留空将随机分配
        CUSTOM_DOMAIN = ""     # 使用自定义域名
        ARGO_TOKEN = ""        # Cloudflare Argo隧道令牌
        ```
        
        **注意事项：**
        - SECRET_KEY 是访问管理面板的密码，请设置一个安全的值
        - 其他配置项都是可选的，可以留空
        """)
        st.stop()
        return
    except Exception as e:
        st.error(f"❌ 读取配置时发生错误: {e}")
        st.stop()
        return
    
    # 根据认证状态显示不同界面
    if st.session_state.authenticated:
        render_main_ui(config)
    else:
        render_login_ui(secret_key)

if __name__ == "__main__":
    main()
