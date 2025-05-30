import sys
import subprocess
import re
import os
import time
import ctypes
import traceback
import io
from ctypes import windll
from subprocess import CREATE_NO_WINDOW  # 添加这个导入用于隐藏命令行窗口

# 导入日志模块
from log_config import logger, log_debug, log_info, log_warning, log_error

# 导入IP配置模块
from ip_config import configure_ipv4, configure_ipv6, is_admin

from PyQt5.QtWidgets import (QApplication, QWidget, QTabWidget, QVBoxLayout, QLabel, QPushButton, 
                             QLineEdit, QComboBox, QHBoxLayout, QCheckBox, QTextEdit, QSpinBox, 
                             QGroupBox, QMessageBox, QGridLayout, QRadioButton, QButtonGroup, QDialog,
                             QProgressDialog)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont

# 获取以太网卡信息（仅限物理网卡）
def get_ethernet_info():
    """获取以太网网卡信息"""
    try:
        # 执行ipconfig /all命令获取所有网络适配器信息
        result = subprocess.run(['ipconfig', '/all'], capture_output=True, text=True, encoding='gbk', creationflags=CREATE_NO_WINDOW)
        output = result.stdout
        
        # 打印原始输出用于调试
        print("获取网卡信息:")
        print(output)
        
        # 分割为每个适配器的段落
        adapters = re.split(r'\n\n', output)
        ethernet_adapters = []
        
        for adapter in adapters:
            # 检查是否为以太网适配器（排除无线、虚拟和隧道适配器）
            if ('以太网适配器' in adapter or 'Ethernet adapter' in adapter) and \
               not any(x in adapter.lower() for x in ['wireless', 'virtual', 'tunnel', 'loopback', '隧道', '虚拟', '无线']):
                
                print(f"找到以太网适配器段落:\n{adapter}")
                
                # 提取适配器名称
                adapter_name_match = re.search(r'(以太网适配器|Ethernet adapter)\s+(.+?)\s*:', adapter)
                if adapter_name_match:
                    adapter_name = adapter_name_match.group(2).strip()
                    
                    # 提取网卡描述（如果有）
                    description_match = re.search(r'描述.+?:\s*(.+)', adapter)
                    description = description_match.group(1).strip() if description_match else adapter_name
                    
                    # 提取MAC地址
                    mac_match = re.search(r'物理地址.+?:\s*(.+)', adapter) or re.search(r'Physical Address.+?:\s*(.+)', adapter)
                    mac = mac_match.group(1).strip() if mac_match else '未知'
                    
                    # 组合网卡名称和MAC地址
                    display_name = f"{description} ({mac})" if mac != '未知' else description
                    
                    ethernet_adapters.append((adapter_name, display_name))
                    print(f"添加网卡: {adapter_name} - 显示为: {display_name}")
        
        return ethernet_adapters
    except Exception as e:
        print(f"获取以太网信息出错: {e}")
        return [('获取网卡信息出错', '获取网卡信息出错')]

# 检查是否具有管理员权限
def is_admin():
    """检查当前程序是否以管理员权限运行"""
    try:
        return windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

# 以管理员权限重新启动程序
def run_as_admin():
    """以管理员权限重新启动程序"""
    try:
        if is_admin():
            return True  # 已经是管理员权限
        else:
            # 获取当前程序的路径
            script = sys.executable
            params = sys.argv
            # 使用ShellExecute以管理员权限启动程序
            ctypes.windll.shell32.ShellExecuteW(None, "runas", script, " ".join(params), None, 1)
            # 退出当前程序
            sys.exit(0)
    except Exception as e:
        print(f"以管理员权限启动失败: {e}")
        return False

# 获取IP配置信息
# 获取IP配置信息
def get_ip_config(nic_name=None):
    try:
        # 使用ipconfig /all命令获取所有网卡信息
        output = subprocess.check_output('ipconfig /all', shell=True, encoding='gbk', errors='ignore', creationflags=CREATE_NO_WINDOW)
        
        # 如果没有指定网卡名称，返回整个输出
        if not nic_name:
            return output
        
        # 从nic_name中提取纯网卡名称（去掉MAC地址部分）
        pure_nic_name = nic_name.split(' (')[0] if ' (' in nic_name else nic_name
        print(f"查找网卡信息: {pure_nic_name}")
        
        # 打印完整的ipconfig输出用于调试
        print("完整的ipconfig输出:")
        print(output)
        
        # 查找网卡信息段落的开始位置
        start_marker = None
        if '以太网适配器 ' + pure_nic_name in output:
            start_marker = '以太网适配器 ' + pure_nic_name
        elif 'Ethernet adapter ' + pure_nic_name in output:
            start_marker = 'Ethernet adapter ' + pure_nic_name
        
        if start_marker:
            # 找到网卡信息段落的开始位置
            start_pos = output.find(start_marker)
            if start_pos != -1:
                # 从开始位置向后查找，直到遇到下一个空行或者下一个网卡信息
                end_pos = output.find('\n\n', start_pos)
                if end_pos == -1:  # 如果没有找到空行，则使用整个剩余部分
                    end_pos = len(output)
                
                # 提取网卡信息段落
                section = output[start_pos:end_pos].strip()
                
                # 确保段落包含足够的信息
                if len(section.split('\n')) < 3:  # 如果行数太少，可能没有包含完整信息
                    # 尝试获取更多行
                    next_adapter_pos = output.find('适配器', end_pos)
                    if next_adapter_pos == -1:
                        next_adapter_pos = output.find('adapter', end_pos)
                    
                    if next_adapter_pos != -1:
                        section = output[start_pos:next_adapter_pos].strip()
                    else:
                        # 如果找不到下一个适配器，则使用更多行
                        end_pos = output.find('\n\n\n', start_pos)
                        if end_pos != -1:
                            section = output[start_pos:end_pos].strip()
                
                print(f"找到网卡信息段落:\n{section}")
                return section
        
        # 如果没有找到精确匹配，尝试模糊匹配
        if pure_nic_name in output:
            lines = output.split('\n')
            for i, line in enumerate(lines):
                if pure_nic_name in line and ('以太网适配器' in line or 'Ethernet adapter' in line):
                    # 找到匹配行，提取从这行开始的一段内容
                    start_idx = i
                    end_idx = i
                    # 向后查找，直到遇到下一个适配器或者文件结束
                    for j in range(i+1, len(lines)):
                        if '适配器' in lines[j] or 'adapter' in lines[j]:
                            end_idx = j - 1
                            break
                        end_idx = j
                    
                    section = '\n'.join(lines[start_idx:end_idx+1])
                    print(f"找到模糊匹配的网卡信息段落:\n{section}")
                    return section
        
        print("未找到指定网卡的信息")
        return "未找到指定网卡的信息"
    except Exception as e:
        print(f"获取IP配置信息出错: {str(e)}")
        import traceback
        traceback.print_exc()
        return f"获取IP配置信息出错: {str(e)}"

# 解析IP配置信息
# 解析IP配置信息
# 解析IP配置信息
def get_dns_servers(nic_name):
    """使用nslookup和route print命令获取DNS服务器信息"""
    ipv4_dns = []
    ipv6_dns = []
    
    try:
        # 使用ipconfig /all命令获取DNS服务器信息（兼容Windows 7）
        ipconfig_output = subprocess.check_output('ipconfig /all', shell=True, encoding='gbk', errors='ignore', creationflags=CREATE_NO_WINDOW)
        
        # 查找指定网卡的部分
        nic_sections = []
        lines = ipconfig_output.split('\n')
        current_section = []
        in_target_section = False
        
        for line in lines:
            if '适配器' in line or 'adapter' in line:
                if current_section and in_target_section:
                    nic_sections.append('\n'.join(current_section))
                current_section = [line]
                in_target_section = nic_name.lower() in line.lower()
            elif line.strip() and in_target_section:
                current_section.append(line)
        
        # 添加最后一个部分
        if current_section and in_target_section:
            nic_sections.append('\n'.join(current_section))
        
        # 从网卡部分提取DNS服务器
        for section in nic_sections:
            # 提取IPv4 DNS服务器
            ipv4_dns_matches = re.findall(r'DNS\s+服务器.+?:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', section)
            if not ipv4_dns_matches:
                ipv4_dns_matches = re.findall(r'DNS\s+Server.+?:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', section)
            
            for addr in ipv4_dns_matches:
                if addr not in ipv4_dns:
                    ipv4_dns.append(addr)
            
            # 查找DNS服务器行及其后续行
            dns_lines = []
            section_lines = section.split('\n')
            dns_section = False
            
            for i, line in enumerate(section_lines):
                if 'DNS' in line and ('服务器' in line or 'Server' in line):
                    dns_lines.append(line)
                    dns_section = True
                elif dns_section and i+1 < len(section_lines):
                    next_line = section_lines[i+1].strip()
                    if next_line and ':' not in next_line:  # 确保下一行不是新的配置项
                        dns_lines.append(next_line)
                    else:
                        dns_section = False
            
            # 从DNS行中提取IPv4地址
            for line in dns_lines:
                ipv4_matches = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                for addr in ipv4_matches:
                    if addr not in ipv4_dns:
                        ipv4_dns.append(addr)
            
            # 从DNS行中提取IPv6地址
            # 简化 IPv6 正则表达式，以避免括号不匹配错误
            # 这个表达式匹配标准的IPv6地址格式，包括压缩形式，但不包括嵌入的IPv4地址或区域索引
            ipv6_pattern = r'([0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4}){7}|([0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4}){0,6})?::([0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4}){0,6})?)'
            
            for line in dns_lines:
                try:
                    ipv6_matches = re.findall(ipv6_pattern, line)
                    for match_tuple in ipv6_matches: # re.findall with groups returns tuples
                        addr = next(s for s in match_tuple if s) # Get the first non-empty string from the tuple
                        if addr: # Ensure addr is not empty
                            # 排除IPv4映射地址和链路本地地址
                            if not addr.startswith('::ffff:') and not addr.startswith('fe80:') and addr not in ipv6_dns:
                                # 确保这是一个有效的IPv6地址
                                if ':' in addr and len(addr) >= 3 and '-' not in addr: # 最小长度调整为3 (e.g. ::1)
                                    # 排除可能是时间格式的值
                                    if not re.match(r'^\d{1,2}:\d{1,2}:\d{1,2}$', addr) and not re.match(r'^\d{1,2}:\d{1,2}$', addr):
                                        ipv6_dns.append(addr)
                                        print(f"在 get_dns_servers 中找到IPv6 DNS: {addr} 从行: {line}")
                except re.error as e:
                    print(f"在 get_dns_servers 中提取IPv6 DNS时发生正则错误: {e}，行: {line}")
                    continue # 继续处理下一行
        
        # 如果上面的方法没有找到IPv4 DNS，尝试使用nslookup命令
        if not ipv4_dns:
            cmd = 'nslookup'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, input='\n', encoding='gbk', errors='ignore', creationflags=CREATE_NO_WINDOW)
            output = result.stdout
            
            # 解析输出
            if output:
                # 提取DNS服务器地址
                dns_pattern = r'服务器:\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
                dns_pattern_en = r'Server:\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
                
                # 尝试中文模式匹配
                dns_matches = re.findall(dns_pattern, output)
                if not dns_matches:
                    # 尝试英文模式匹配
                    dns_matches = re.findall(dns_pattern_en, output)
                
                for addr in dns_matches:
                    if addr not in ipv4_dns:
                        ipv4_dns.append(addr)
                        print(f"从nslookup中找到IPv4 DNS: {addr}")
        
        # 如果上面的方法没有找到IPv6 DNS，尝试直接从输出中查找已知的公共IPv6 DNS服务器
        known_ipv6_dns = [
            '2001:4860:4860::8888',  # Google
            '2001:4860:4860::8844',  # Google
            '2606:4700:4700::1111',  # Cloudflare
            '2606:4700:4700::1001',  # Cloudflare
            '2400:3200::1',          # AliDNS
            '2400:3200:baba::1',     # AliDNS
            '2409:8057:2000:6::8',   # 中国电信
            '2409:8057:2000:2::8',   # 中国电信
            '2408:8899::8',          # 中国联通
            '2408:8888::8'           # 中国联通
        ]
        
        for dns_server in known_ipv6_dns: # 变量名修改以示区分
            if dns_server in ipconfig_output and dns_server not in ipv6_dns:
                ipv6_dns.append(dns_server)
                print(f"  从已知列表中找到IPv6 DNS: {dns_server}")
        
        # 如果仍然没有找到IPv4 DNS，尝试使用常见的DNS服务器
        if not ipv4_dns:
            print("仍然没有找到IPv4 DNS，尝试使用常见DNS服务器和网关...")
            common_ipv4_dns = [
                '192.168.1.1',     # 常见家用路由器
                '192.168.0.1',     # 常见家用路由器
                '8.8.8.8',         # Google
                '8.8.4.4',         # Google
                '114.114.114.114', # 114DNS
                '114.114.115.115', # 114DNS
                '223.5.5.5',       # AliDNS
                '223.6.6.6',       # AliDNS
                '119.29.29.29',    # DNSPod
                '180.76.76.76'     # 百度DNS
            ]
            
            # 检查网关地址，通常网关也是DNS服务器
            print("  检查网关地址作为IPv4 DNS候选...")
            gateway_match = re.search(r'默认网关.+?:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', ipconfig_output)
            if not gateway_match:
                gateway_match = re.search(r'Default Gateway.+?:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', ipconfig_output)
            
            if gateway_match:
                gateway = gateway_match.group(1)
                print(f"    检测到网关: {gateway}")
                if gateway not in ipv4_dns:
                    ipv4_dns.append(gateway)
                    print(f"      使用网关作为IPv4 DNS: {gateway}")
            else:
                print("    未找到默认网关信息。")
            
            # 如果仍然没有找到，尝试使用常见的DNS服务器
            print("  尝试从常见DNS列表中查找...")
            for common_dns in common_ipv4_dns: # 变量名修改
                if common_dns in ipconfig_output and common_dns not in ipv4_dns:
                    # 进一步确认 common_dns 是否really一个DNS条目，而不仅仅是输出中的某个IP
                    # 这是一个简化处理，实际可能需要更复杂的上下文判断
                    if f"DNS Servers . . . . . . . . . . . : {common_dns}" in ipconfig_output or f"DNS 服务器 . . . . . . . . . . . : {common_dns}" in ipconfig_output or common_dns == gateway:
                        ipv4_dns.append(common_dns)
                        print(f"    从常见DNS列表中找到IPv4 DNS: {common_dns}")
        
        print(f"最终获取的IPv4 DNS: {ipv4_dns}")
        print(f"最终获取的IPv6 DNS: {ipv6_dns}")
        
        return ipv4_dns, ipv6_dns
    except Exception as e:
        print(f"获取DNS服务器信息出错: {str(e)}")
        import traceback
        traceback.print_exc()
        return [], []

def parse_ip_config(config_text):
    """解析ipconfig输出的配置信息"""
    info = {
        'IPv4': '未知',
        'IPv6': '未知',
        'Mask_v4': '未知',
        'Mask_v6': '未知',
        'Gateway_v4': '未知',
        'Gateway_v6': '未知',
        'DNS_v4': '未知',
        'DNS_v6': '未知',
        'MAC': '未知',
        'DHCP': False
    }
    
    # 用于存储多个DNS服务器地址
    ipv4_dns_servers = []
    ipv6_dns_servers = []
    
    # 标记是否正在处理网关或DNS部分
    gateway_section = False
    dns_section = False
    
    # 提取网卡名称
    nic_name = None
    for line in config_text.splitlines():
        if '适配器' in line or 'adapter' in line:
            nic_name_match = re.search(r'适配器\s+(.+?):|adapter\s+(.+?):', line)
            if nic_name_match:
                nic_name = nic_name_match.group(1) or nic_name_match.group(2)
                break
    
    # 如果找到网卡名称，使用nslookup获取DNS服务器信息
    if nic_name:
        ipv4_dns_from_cmd, ipv6_dns_from_cmd = get_dns_servers(nic_name)
        if ipv4_dns_from_cmd:
            ipv4_dns_servers = ipv4_dns_from_cmd
            # 立即更新info字典中的DNS_v4
            info['DNS_v4'] = '\n'.join(ipv4_dns_servers)
            print(f"从get_dns_servers获取的IPv4 DNS: {ipv4_dns_servers}")
        if ipv6_dns_from_cmd:
            ipv6_dns_servers = ipv6_dns_from_cmd
            # 立即更新info字典中的DNS_v6
            info['DNS_v6'] = '\n'.join(ipv6_dns_servers)
            print(f"从get_dns_servers获取的IPv6 DNS: {ipv6_dns_servers}")
    
    # 存储找到的所有IPv6地址
    all_ipv6_addresses = []
    
    # 逐行解析配置信息
    for line in config_text.splitlines():
        line = line.strip()
        print(f"解析行: {line}")
        
        # 提取IPv4地址
        if ('IPv4 地址' in line or 'IPv4 Address' in line) and ':' in line:
            parts = line.split(':', 1)
            if len(parts) > 1 and parts[1].strip():
                # 提取IPv4地址，处理带有(首选)或其他标记的情况
                ip_part = parts[1].strip()
                # 使用正则表达式提取IPv4地址部分
                ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', ip_part)
                if ip_match:
                    info['IPv4'] = ip_match.group(1)
                    print(f"找到IPv4: {info['IPv4']}")
        
        # 提取IPv6地址
        elif ('IPv6 地址' in line or 'IPv6 Address' in line) and ':' in line:
            parts = line.split(':', 1)
            if len(parts) > 1 and parts[1].strip():
                # 提取IPv6地址，处理带有(首选)或其他标记的情况
                ip_part = parts[1].strip()
                # 使用正则表达式提取IPv6地址部分 - 匹配包含冒号的IPv6格式
                ip_match = re.search(r'([0-9a-fA-F:]+(?::[0-9a-fA-F]+)+)', ip_part)
                if ip_match:
                    ipv6_addr = ip_match.group(1)
                    # 将找到的IPv6地址添加到列表中
                    all_ipv6_addresses.append(ipv6_addr)
                    print(f"找到IPv6地址: {ipv6_addr}")
                    
                    # 尝试从IPv6地址中提取前缀长度
                    prefix_match = re.search(r'/([0-9]+)', ip_part)
                    if prefix_match:
                        info['Mask_v6'] = prefix_match.group(1)
                        print(f"从IPv6地址行 '{original_line_for_prefix}' 中找到前缀长度: {info['Mask_v6']}")
                    elif '临时' not in ip_part and '(Preferred)' not in ip_part:
                        # 对于非临时IPv6地址，设置默认前缀长度
                        if ipv6_addr.startswith('fe80:'):
                            # 链路本地地址的前缀长度通常是64
                            info['Mask_v6'] = '64'
                            print(f"链路本地IPv6地址，设置前缀长度为: {info['Mask_v6']}")
                        elif ipv6_addr.startswith('2001:') or ipv6_addr.startswith('2400:') or ipv6_addr.startswith('2409:'):
                            # 全局单播地址的前缀长度通常是64
                            info['Mask_v6'] = '64'
                            print(f"全局单播IPv6地址，设置默认前缀长度为: {info['Mask_v6']}")
        
        # 提取子网掩码 (IPv4)
        elif ('子网掩码' in line or 'Subnet Mask' in line) and ':' in line:
            parts = line.split(':', 1)
            if len(parts) > 1 and parts[1].strip():
                # 提取子网掩码，处理可能的标记
                mask_part = parts[1].strip()
                mask_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', mask_part)
                if mask_match:
                    info['Mask_v4'] = mask_match.group(1)
                    print(f"找到IPv4子网掩码: {info['Mask_v4']}")
        
        # 提取IPv6前缀长度
        elif ('前缀长度' in line or 'Prefix Length' in line) and ':' in line:
            parts = line.split(':', 1)
            if len(parts) > 1 and parts[1].strip():
                # 提取前缀长度
                prefix_part = parts[1].strip()
                prefix_match = re.search(r'(\d+)', prefix_part)
                if prefix_match:
                    info['Mask_v6'] = prefix_match.group(1)
                    print(f"找到IPv6前缀长度: {info['Mask_v6']}")
        
        # 处理默认网关部分
        elif ('默认网关' in line or 'Default Gateway' in line) and ':' in line:
            parts = line.split(':', 1)
            gateway_section = True  # 标记开始处理网关部分
            
            if len(parts) > 1 and parts[1].strip():
                # 提取网关地址，处理可能的标记
                gateway_part = parts[1].strip()
                # 尝试匹配IPv6网关
                gateway_match = re.search(r'([0-9a-fA-F:]+(?::[0-9a-fA-F]+)+)', gateway_part)
                if gateway_match:
                    info['Gateway_v6'] = gateway_match.group(1)
                    print(f"找到IPv6默认网关: {info['Gateway_v6']}")
                # 尝试匹配IPv4网关
                else:
                    gateway_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', gateway_part)
                    if gateway_match:
                        info['Gateway_v4'] = gateway_match.group(1)
                        print(f"找到IPv4默认网关: {info['Gateway_v4']}")
        
        # 处理网关部分的后续行
        elif gateway_section and line.strip() and not ':' in line:
            # 检查是否为IPv4地址
            ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
            if ip_match:
                info['Gateway_v4'] = ip_match.group(1)
                print(f"找到IPv4默认网关(后续行): {info['Gateway_v4']}")
            # 检查是否为IPv6地址
            else:
                ip_match = re.search(r'([0-9a-fA-F:]+(?::[0-9a-fA-F]+)+)', line)
                if ip_match:
                    info['Gateway_v6'] = ip_match.group(1)
                    print(f"找到IPv6默认网关(后续行): {info['Gateway_v6']}")
        
        # 如果遇到新的配置项，结束网关部分处理
        elif gateway_section and ':' in line:
            gateway_section = False
        
        # 提取DNS服务器部分
        elif ('DNS' in line and '服务器' in line or 'DNS Server' in line) and ':' in line:
            parts = line.split(':', 1)
            dns_section = True  # 标记开始处理DNS部分
            
            if len(parts) > 1 and parts[1].strip():
                # 提取DNS服务器地址，处理可能的标记
                dns_part = parts[1].strip()
                # 尝试匹配IPv6 DNS，包括 ::ffff: 前缀的IPv4映射地址
                ipv6_pattern = r'([0-9a-fA-F:]+(?::[0-9a-fA-F]+)+)'
                dns_match = re.findall(ipv6_pattern, dns_part)
                for addr in dns_match:
                    # 检查是否为IPv4映射地址
                    if addr.startswith('::ffff:'):
                        # 提取IPv4部分
                        ipv4_part = addr.replace('::ffff:', '')
                        if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', ipv4_part) and ipv4_part not in ipv4_dns_servers:
                            ipv4_dns_servers.append(ipv4_part)
                            print(f"从IPv6映射地址中找到IPv4 DNS服务器: {ipv4_part}")
                    elif addr not in ipv6_dns_servers:
                        ipv6_dns_servers.append(addr)
                        print(f"找到IPv6 DNS服务器: {addr}")
                # 尝试匹配IPv4 DNS
                dns_match = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', dns_part)
                for addr in dns_match:
                    if addr not in ipv4_dns_servers:
                        ipv4_dns_servers.append(addr)
                        print(f"找到IPv4 DNS服务器: {addr}")
        # 处理DNS部分的后续行（缩进或空白开头）
        elif dns_section and (line.startswith(' ') or line.startswith('\t')) and line.strip():
            # 尝试匹配IPv6 DNS，包括 ::ffff: 前缀的IPv4映射地址
            ipv6_pattern = r'([0-9a-fA-F:]+(?::[0-9a-fA-F]+)+)'
            dns_match = re.findall(ipv6_pattern, line)
            for addr in dns_match:
                # 检查是否为IPv4映射地址
                if addr.startswith('::ffff:'):
                    # 提取IPv4部分
                    ipv4_part = addr.replace('::ffff:', '')
                    if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', ipv4_part) and ipv4_part not in ipv4_dns_servers:
                        ipv4_dns_servers.append(ipv4_part)
                        print(f"从IPv6映射地址中找到IPv4 DNS服务器(后续行): {ipv4_part}")
                elif addr not in ipv6_dns_servers:
                    ipv6_dns_servers.append(addr)
                    print(f"找到IPv6 DNS服务器(后续行): {addr}")
            # 尝试匹配IPv4 DNS
            dns_match = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
            for addr in dns_match:
                if addr not in ipv4_dns_servers:
                    ipv4_dns_servers.append(addr)
                    print(f"找到IPv4 DNS服务器(后续行): {addr}")
        # 如果遇到新的配置项，结束DNS部分处理
        elif dns_section and ':' in line:
            dns_section = False
        
        # 提取MAC地址
        elif ('物理地址' in line or 'Physical Address' in line) and ':' in line:
            parts = line.split(':', 1)
            if len(parts) > 1 and parts[1].strip():
                info['MAC'] = parts[1].strip()
                print(f"找到MAC地址: {info['MAC']}")
        
        # 判断是否为DHCP
        elif 'DHCP' in line and ('已启用' in line or 'Enabled' in line) and ':' in line:
            parts = line.split(':', 1)
            if len(parts) > 1:
                dhcp_value = parts[1].strip()
                info['DHCP'] = dhcp_value in ['是', 'Yes']
                print(f"DHCP已启用: {info['DHCP']}")
    
    # 处理收集到的IPv6地址
    if all_ipv6_addresses:
        # 收集所有全局IPv6地址（不是链路本地地址）
        global_ipv6_addresses = [addr for addr in all_ipv6_addresses if not addr.startswith('fe80:')]
        
        # 如果找到多个全局IPv6地址，只使用第一个
        if len(global_ipv6_addresses) > 1:
            # 只使用第一个全局IPv6地址
            info['IPv6'] = global_ipv6_addresses[0]
            print(f"发现多个全局IPv6地址，只使用第一个: {info['IPv6']}，共有{len(global_ipv6_addresses)}个地址")
        # 如果只找到一个全局IPv6地址，使用它
        elif len(global_ipv6_addresses) == 1:
            info['IPv6'] = global_ipv6_addresses[0]
            print(f"使用全局IPv6地址: {info['IPv6']}")
        # 否则使用第一个找到的IPv6地址（可能是链路本地地址）
        elif all_ipv6_addresses:
            info['IPv6'] = all_ipv6_addresses[0]
            print(f"使用链路本地IPv6地址: {info['IPv6']}")
            # 链路本地地址的前缀长度通常是64
            if info['Mask_v6'] == '未知' and info['IPv6'].startswith('fe80:'):
                info['Mask_v6'] = '64'
                print(f"链路本地IPv6地址，设置前缀长度为: {info['Mask_v6']}")
    
    # 合并所有DNS服务器
    if ipv4_dns_servers:
        info['DNS_v4'] = '\n'.join(ipv4_dns_servers)
        print(f"最终收集到的IPv4 DNS: {ipv4_dns_servers}")
    if ipv6_dns_servers:
        info['DNS_v6'] = '\n'.join(ipv6_dns_servers)
        print(f"最终收集到的IPv6 DNS: {ipv6_dns_servers}")
    print(f"最终收集到的IPv6前缀长度: {info['Mask_v6']}")
    
    # 如果DNS服务器信息仍然未知，尝试使用get_dns_servers函数获取
    if info['DNS_v4'] == '未知' or info['DNS_v6'] == '未知':
        print("尝试使用get_dns_servers函数获取DNS服务器信息")
        ipv4_dns_list, ipv6_dns_list = get_dns_servers(nic_name)
        
        # 更新IPv4 DNS服务器信息
        if ipv4_dns_list and info['DNS_v4'] == '未知':
            info['DNS_v4'] = '\n'.join(ipv4_dns_list)
            print(f"使用get_dns_servers获取的IPv4 DNS: {ipv4_dns_list}")
        
        # 更新IPv6 DNS服务器信息
        if ipv6_dns_list and info['DNS_v6'] == '未知':
            info['DNS_v6'] = '\n'.join(ipv6_dns_list)
            print(f"使用get_dns_servers获取的IPv6 DNS: {ipv6_dns_list}")
    
    return info

# Ping测试线程
class PingThread(QThread):
    update_signal = pyqtSignal(str)
    
    def __init__(self, target, count, size, protocol='IPv4'):
        super().__init__()
        self.target = target
        self.count = count
        self.size = size
        self.protocol = protocol
    
    def run(self):
        try:
            # 构建ping命令
            cmd = ['ping']
            if self.protocol == 'IPv6':
                cmd.append('-6')
            cmd.extend(['-n', str(self.count), '-l', str(self.size), self.target])
            
            # 执行ping命令
            process = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                universal_newlines=True,
                encoding='gbk',
                errors='ignore',
                creationflags=CREATE_NO_WINDOW
            )
            
            # 实时获取输出
            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    self.update_signal.emit(output.strip())
            
            # 获取错误信息
            stderr = process.stderr.read()
            if stderr:
                self.update_signal.emit(f"错误: {stderr}")
                
        except Exception as e:
            self.update_signal.emit(f"Ping测试出错: {str(e)}")

# IP配置对话框
class IPConfigDialog(QDialog):
    def __init__(self, parent=None, ip_info=None, is_ipv4=True):
        super().__init__(parent)
        self.ip_info = ip_info or {}
        self.is_ipv4 = is_ipv4
        self.init_ui()
    
    def init_ui(self):
        self.setWindowTitle('IP配置')
        self.resize(400, 300)
        
        layout = QVBoxLayout(self)
        
        # 自动/手动分配选项
        self.auto_group = QButtonGroup(self)
        self.auto_radio = QRadioButton('自动获取IP地址')
        self.manual_radio = QRadioButton('使用下面的IP地址')
        self.auto_group.addButton(self.auto_radio)
        self.auto_group.addButton(self.manual_radio)
        
        # 默认选择当前状态
        if self.ip_info.get('DHCP', False):
            self.auto_radio.setChecked(True)
        else:
            self.manual_radio.setChecked(True)
        
        layout.addWidget(self.auto_radio)
        layout.addWidget(self.manual_radio)
        
        # IP配置表单
        form_layout = QGridLayout()
        
        # IPv4配置
        if self.is_ipv4:
            self.ip_label = QLabel('IP地址:')
            self.ip_input = QLineEdit(self.ip_info.get('IPv4', ''))
            form_layout.addWidget(self.ip_label, 0, 0)
            form_layout.addWidget(self.ip_input, 0, 1)
            
            self.mask_label = QLabel('子网掩码:')
            self.mask_input = QLineEdit(self.ip_info.get('Mask_v4', ''))
            form_layout.addWidget(self.mask_label, 1, 0)
            form_layout.addWidget(self.mask_input, 1, 1)
            
            self.gateway_label = QLabel('默认网关:')
            self.gateway_input = QLineEdit(self.ip_info.get('Gateway_v4', ''))
            form_layout.addWidget(self.gateway_label, 2, 0)
            form_layout.addWidget(self.gateway_input, 2, 1)
            
            self.dns_primary_label = QLabel('首选DNS服务器:') # 修改
            dns_v4_servers = self.ip_info.get('DNS_v4', '').split('\n')
            primary_dns_v4 = dns_v4_servers[0] if dns_v4_servers else ''
            self.dns_primary_input = QLineEdit(primary_dns_v4) # 修改
            form_layout.addWidget(self.dns_primary_label, 3, 0)
            form_layout.addWidget(self.dns_primary_input, 3, 1)

            self.dns_secondary_label = QLabel('备用DNS服务器:') # 新增
            secondary_dns_v4 = dns_v4_servers[1] if len(dns_v4_servers) > 1 else ''
            self.dns_secondary_input = QLineEdit(secondary_dns_v4) # 新增
            form_layout.addWidget(self.dns_secondary_label, 4, 0)
            form_layout.addWidget(self.dns_secondary_input, 4, 1)
        # IPv6配置
        else:
            self.ip_label = QLabel('IPv6地址:')
            self.ip_input = QLineEdit(self.ip_info.get('IPv6', ''))
            form_layout.addWidget(self.ip_label, 0, 0)
            form_layout.addWidget(self.ip_input, 0, 1)
            
            # 添加IPv6相关配置
            self.prefix_label = QLabel('前缀长度:')
            self.prefix_input = QLineEdit(self.ip_info.get('Mask_v6', ''))
            form_layout.addWidget(self.prefix_label, 1, 0)
            form_layout.addWidget(self.prefix_input, 1, 1)
            
            self.gateway_label = QLabel('默认网关:')
            self.gateway_input = QLineEdit(self.ip_info.get('Gateway_v6', ''))
            form_layout.addWidget(self.gateway_label, 2, 0)
            form_layout.addWidget(self.gateway_input, 2, 1)
            
            self.dns_primary_label = QLabel('首选DNS服务器:') # 修改变量名
            dns_v6_servers = self.ip_info.get('DNS_v6', '').split('\n')
            primary_dns_v6 = dns_v6_servers[0] if dns_v6_servers else ''
            self.dns_primary_input = QLineEdit(primary_dns_v6) # 修改变量名
            form_layout.addWidget(self.dns_primary_label, 3, 0)
            form_layout.addWidget(self.dns_primary_input, 3, 1)

            self.dns_secondary_label = QLabel('备用DNS服务器:') # 新增备用DNS标签
            secondary_dns_v6 = dns_v6_servers[1] if len(dns_v6_servers) > 1 else ''
            self.dns_secondary_input = QLineEdit(secondary_dns_v6) # 新增备用DNS输入框
            form_layout.addWidget(self.dns_secondary_label, 4, 0)
            form_layout.addWidget(self.dns_secondary_input, 4, 1)
        
        layout.addLayout(form_layout)
        
        # 按钮
        button_layout = QHBoxLayout()
        self.save_btn = QPushButton('保存')
        self.cancel_btn = QPushButton('取消')
        
        self.save_btn.clicked.connect(self.accept)
        self.cancel_btn.clicked.connect(self.reject)
        
        button_layout.addWidget(self.save_btn)
        button_layout.addWidget(self.cancel_btn)
        layout.addLayout(button_layout)
        
        # 根据自动/手动选择启用/禁用输入框
        self.auto_radio.toggled.connect(self.toggle_inputs)
        # 确保在 toggle_inputs 调用前，所有相关的 input 都已创建
        if not hasattr(self, 'dns_primary_input'): # 增加保护，如果ipv4分支没有创建，则在此创建
            # 这个分支理论上不应该进入，因为 is_ipv4 True 时应该已经创建
            # 但作为双重保险，如果因为某些逻辑错误未创建，这里补充创建，避免 AttributeError
            dns_servers_fallback = self.ip_info.get('DNS_v4' if self.is_ipv4 else 'DNS_v6', '').split('\n')
            primary_dns_fallback = dns_servers_fallback[0] if dns_servers_fallback else ''
            self.dns_primary_input = QLineEdit(primary_dns_fallback)
            secondary_dns_fallback = dns_servers_fallback[1] if len(dns_servers_fallback) > 1 else ''
            self.dns_secondary_input = QLineEdit(secondary_dns_fallback)

        self.toggle_inputs(self.auto_radio.isChecked())
    
    def toggle_inputs(self, is_auto):
        enabled = not is_auto
        self.ip_input.setEnabled(enabled)
        if hasattr(self, 'mask_input'):
            self.mask_input.setEnabled(enabled)
        if hasattr(self, 'prefix_input'):
            self.prefix_input.setEnabled(enabled)
        if hasattr(self, 'gateway_input'):
            self.gateway_input.setEnabled(enabled)
        self.dns_primary_input.setEnabled(enabled) # 修改变量名
        self.dns_secondary_input.setEnabled(enabled) # 新增备用DNS输入框的控制
    
    def get_config(self):
        config = {}
        config['auto'] = self.auto_radio.isChecked()
        
        if not config['auto']:
            if self.is_ipv4:
                config['ip'] = self.ip_input.text()
                config['mask'] = self.mask_input.text()
                config['gateway'] = self.gateway_input.text()
                # 合并主备DNS
                dns_servers = []
                if self.dns_primary_input.text():
                    dns_servers.append(self.dns_primary_input.text())
                if self.dns_secondary_input.text():
                    dns_servers.append(self.dns_secondary_input.text())
                # 使用逗号分隔DNS服务器，这样更符合PowerShell命令的格式
                config['dns'] = ','.join(dns_servers)
            else:
                config['ipv6'] = self.ip_input.text()
                config['prefix'] = self.prefix_input.text()
                config['gateway_v6'] = self.gateway_input.text()
                # 合并主备DNS
                dns_servers = []
                if self.dns_primary_input.text():
                    dns_servers.append(self.dns_primary_input.text())
                if self.dns_secondary_input.text():
                    dns_servers.append(self.dns_secondary_input.text())
                # 使用换行符分隔DNS服务器，确保与IPv4保持一致的格式
                config['dns_v6'] = '\n'.join(dns_servers) # 使用换行符分隔
        
        return config
        
    def apply_config(self, nic_name):
        """应用IP配置更改"""
        config = self.get_config()
        success = False
        error_msg = ""
        
        # 创建进度对话框
        progress = QProgressDialog("正在应用IP配置...", "取消", 0, 100, self)
        progress.setWindowTitle("配置进度")
        progress.setWindowModality(Qt.WindowModal)
        progress.setMinimumDuration(0)  # 立即显示
        progress.setValue(0)
        
        try:
            if config['auto']:
                # 设置自动获取IP地址
                if self.is_ipv4:
                    progress.setLabelText("正在设置IPv4为自动获取...")
                    progress.setValue(10)
                    # 设置IPv4为自动获取
                    cmd = f'netsh interface ipv4 set address name="{nic_name}" source=dhcp'
                    subprocess.run(cmd, shell=True, check=True, creationflags=CREATE_NO_WINDOW)
                    progress.setValue(40)
                    
                    progress.setLabelText("正在设置DNS为自动获取...")
                    # 设置DNS为自动获取
                    cmd = f'netsh interface ipv4 set dnsservers name="{nic_name}" source=dhcp'
                    subprocess.run(cmd, shell=True, check=True, creationflags=CREATE_NO_WINDOW)
                    progress.setValue(70)
                    
                    progress.setLabelText("正在验证配置...")
                    # 验证配置是否成功
                    verify_cmd = f'netsh interface ipv4 show config name="{nic_name}"'
                    verify_result = subprocess.run(verify_cmd, shell=True, capture_output=True, text=True, creationflags=CREATE_NO_WINDOW)
                    if 'DHCP已启用' not in verify_result.stdout and 'DHCP enabled' not in verify_result.stdout:
                        raise subprocess.CalledProcessError(returncode=1, cmd=cmd, output="DHCP配置验证失败")
                    logger.info("IPv4 DHCP配置成功")
                    progress.setValue(100)
                else:
                    progress.setLabelText("正在设置IPv6为自动获取...")
                    progress.setValue(10)
                    # 设置IPv6为自动获取
                    try:
                        cmd = f'netsh interface ipv6 set address name="{nic_name}" source=dhcp'
                        subprocess.run(cmd, shell=True, check=True, creationflags=CREATE_NO_WINDOW)
                        progress.setValue(40)
                        
                        progress.setLabelText("正在设置DNS为自动获取...")
                        # 设置DNS为自动获取
                        cmd = f'netsh interface ipv6 set dnsservers name="{nic_name}" source=dhcp'
                        subprocess.run(cmd, shell=True, check=True, creationflags=CREATE_NO_WINDOW)
                        progress.setValue(70)
                        
                        progress.setLabelText("正在验证配置...")
                        # 验证配置是否成功
                        verify_cmd = f'netsh interface ipv6 show address interface="{nic_name}"'
                        verify_result = subprocess.run(verify_cmd, shell=True, capture_output=True, text=True, creationflags=CREATE_NO_WINDOW)
                        if 'DHCP' not in verify_result.stdout:
                            raise subprocess.CalledProcessError(returncode=1, cmd=cmd, output="DHCP配置验证失败")
                        logger.info("IPv6 DHCP配置成功")
                        progress.setValue(100)
                    except Exception as e:
                        logger.error(f"IPv6自动配置失败: {str(e)}")
                        progress.setLabelText("正在尝试使用PowerShell配置IPv6 DHCP...")
                        # 尝试使用PowerShell配置IPv6 DHCP
                        try:
                            ps_cmd = f'powershell -Command "Get-NetAdapter -InterfaceAlias \"{nic_name}\" | Set-NetIPInterface -Dhcp Enabled -AddressFamily IPv6"'
                            subprocess.run(ps_cmd, shell=True, check=True, creationflags=CREATE_NO_WINDOW)
                            progress.setValue(85)
                            ps_cmd = f'powershell -Command "Get-NetAdapter -InterfaceAlias \"{nic_name}\" | Set-DnsClientServerAddress -ResetServerAddresses -AddressFamily IPv6"'
                            subprocess.run(ps_cmd, shell=True, check=True, creationflags=CREATE_NO_WINDOW)
                            logger.info("使用PowerShell配置IPv6 DHCP成功")
                            progress.setValue(100)
                        except Exception as ps_e:
                            logger.error(f"PowerShell配置IPv6 DHCP失败: {str(ps_e)}")
                            # 不抛出异常，让程序继续运行
                success = True
            else:
                # 设置手动IP地址
                if self.is_ipv4:
                    progress.setLabelText("正在准备IPv4配置参数...")
                    progress.setValue(10)
                    # 准备IPv4配置参数
                    ipv4_config = {
                        'ipv4': config['ip'],
                        'mask': config['mask'],
                        'gateway': config['gateway'],
                        'dns': config['dns']
                    }
                    
                    progress.setLabelText("正在应用IPv4配置...")
                    progress.setValue(30)
                    # 调用IPv4配置函数
                    success, error_msg = configure_ipv4(nic_name, ipv4_config)
                    if success:
                        logger.info(f"IPv4配置成功: {config['ip']}")
                        progress.setValue(100)
                    else:
                        logger.error(f"IPv4配置失败: {error_msg}")
                        progress.setValue(100)
                else:
                    progress.setLabelText("正在准备IPv6配置参数...")
                    progress.setValue(10)
                    # 准备IPv6配置参数
                    ipv6_config = {
                        'ipv6': config['ipv6'],
                        'prefix': config['prefix'],
                        'gateway_v6': config['gateway_v6'],
                        'dns_v6': config['dns_v6']
                    }
                    
                    progress.setLabelText("正在应用IPv6配置...")
                    progress.setValue(30)
                    # 调用IPv6配置函数
                    try:
                        success, error_msg = configure_ipv6(nic_name, ipv6_config)
                        if success and not error_msg:
                            logger.info(f"IPv6配置完全成功: {config['ipv6']}")
                            progress.setValue(100)
                        elif success and error_msg:
                            logger.warning(f"IPv6配置部分成功: {error_msg}")
                            progress.setValue(100)
                        else:
                            logger.error(f"IPv6配置失败: {error_msg}")
                            progress.setValue(100)
                    except Exception as e:
                        logger.error(f"IPv6配置函数执行出错: {str(e)}")
                        error_msg = f"IPv6配置函数执行出错: {str(e)}"
                        success = False
                        progress.setValue(100)
                        
                    # 如果模块化配置失败，尝试使用原始方法
                    # 设置IPv6地址和前缀长度
                    if config['ipv6'] and config['prefix']:
                        success = False
                        # 减少IPv6地址设置命令尝试，优先使用Windows 7兼容的命令
                        ipv6_cmds = [
                            # 格式1: 使用add命令 (Windows 7兼容)
                            f'netsh interface ipv6 add address "{nic_name}" {config["ipv6"]}/{config["prefix"]}',
                            # 格式2: 使用store=persistent参数 (Windows 7兼容)
                            f'netsh interface ipv6 add address "{nic_name}" {config["ipv6"]}/{config["prefix"]} store=persistent',
                            # 格式3: 使用name参数 (Windows 7兼容)
                            f'netsh interface ipv6 add address name="{nic_name}" address={config["ipv6"]} prefixlength={config["prefix"]}'
                        ]
                        
                        # 依次尝试不同的命令格式
                        for i, cmd in enumerate(ipv6_cmds):
                            try:
                                print(f"尝试IPv6地址设置命令格式{i+1}: {cmd}")
                                subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
                                # 验证配置是否成功
                                verify_cmd = f'netsh interface ipv6 show address interface="{nic_name}"'
                                verify_result = subprocess.run(verify_cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
                                if not verify_result.stdout or config['ipv6'] not in verify_result.stdout:
                                    raise subprocess.CalledProcessError(returncode=1, cmd=cmd, output="IPv6地址配置验证失败")
                                print(f"IPv6地址设置成功: {cmd}")
                                success = True
                                break  # 成功则跳出循环
                            except subprocess.CalledProcessError as e:
                                print(f"IPv6地址设置命令格式{i+1}失败: {e}, 返回码: {e.returncode}")
                                if hasattr(e, 'stdout') and e.stdout:
                                    print(f"命令输出: {e.stdout}")
                                if hasattr(e, 'stderr') and e.stderr:
                                    print(f"错误输出: {e.stderr}")
                                # 继续尝试下一个命令格式
                            except Exception as e:
                                print(f"执行IPv6地址设置命令时出错: {str(e)}")
                                # 继续尝试下一个命令格式
                        
                        # 如果所有IPv6地址设置命令都失败
                            if not success:
                                progress.setLabelText("正在尝试更多IPv6地址设置方法...")
                                progress.setValue(70)
                                print("所有IPv6地址设置命令格式都失败，尝试使用更多命令格式")
                                # 尝试更多的命令格式，但减少不必要的尝试，优先使用Windows 7兼容的命令
                                additional_ipv6_cmds = [
                                    # 格式7: 使用临时地址 (Windows 7兼容)
                                    f'netsh interface ipv6 add address "{nic_name}" {config["ipv6"]}/{config["prefix"]} type=unicast',
                                    # 格式8: 使用address参数 (Windows 7兼容)
                                    f'netsh interface ipv6 add address "{nic_name}" address={config["ipv6"]} prefixlength={config["prefix"]}'
                                ]
                            
                            for i, cmd in enumerate(additional_ipv6_cmds):
                                try:
                                    print(f"尝试额外IPv6地址设置命令格式{i+1}: {cmd}")
                                    subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
                                    # 验证配置是否成功
                                    verify_cmd = f'netsh interface ipv6 show address interface="{nic_name}"'
                                    verify_result = subprocess.run(verify_cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
                                    if not verify_result.stdout or config['ipv6'] not in verify_result.stdout:
                                        raise subprocess.CalledProcessError(returncode=1, cmd=cmd, output="IPv6地址配置验证失败")
                                    print(f"额外IPv6地址设置命令成功: {cmd}")
                                    success = True
                                    break  # 成功则跳出循环
                                except subprocess.CalledProcessError as e:
                                    print(f"额外IPv6地址设置命令格式{i+1}失败: {e}, 返回码: {e.returncode}")
                                    if hasattr(e, 'stdout') and e.stdout:
                                        print(f"命令输出: {e.stdout}")
                                    if hasattr(e, 'stderr') and e.stderr:
                                        print(f"错误输出: {e.stderr}")
                                    # 继续尝试下一个命令格式
                                except Exception as e:
                                    print(f"执行额外IPv6地址设置命令时出错: {str(e)}")
                                    # 继续尝试下一个命令格式
                            
                            # 如果仍然失败，记录错误但不抛出异常，继续尝试设置网关
                            if not success:
                                logger.error("所有IPv6地址设置命令都失败，但将继续尝试设置网关和DNS")
                                error_msg = "IPv6地址设置失败，但将继续尝试设置网关和DNS"
                                # 不设置success=False，让程序继续执行
                        
                        # 设置IPv6网关
                        if config['gateway_v6']:
                            progress.setLabelText("正在配置IPv6网关...")
                            progress.setValue(90)
                            gateway_success = False
                            # 尝试多种IPv6网关设置命令格式
                            gateway_cmds = [
                                # 格式1: 最基本的格式
                                f'netsh interface ipv6 add route ::/0 "{nic_name}" {config["gateway_v6"]}',
                                # 格式2: 使用interface和nexthop参数
                                f'netsh interface ipv6 add route ::/0 interface="{nic_name}" nexthop={config["gateway_v6"]}',
                                # 格式3: 使用store=persistent参数
                                f'netsh interface ipv6 add route ::/0 "{nic_name}" {config["gateway_v6"]} store=persistent',
                                # 格式4: 使用metric参数
                                f'netsh interface ipv6 add route ::/0 "{nic_name}" {config["gateway_v6"]} metric=1',
                            ]
                            
                            # 依次尝试不同的网关命令格式
                            for i, cmd in enumerate(gateway_cmds):
                                try:
                                    print(f"尝试IPv6网关设置命令格式{i+1}: {cmd}")
                                    subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
                                    # 验证配置是否成功
                                    verify_cmd = f'netsh interface ipv6 show address interface="{nic_name}"'
                                    verify_result = subprocess.run(verify_cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
                                    if not verify_result.stdout or config['ipv6'] not in verify_result.stdout:
                                        raise subprocess.CalledProcessError(returncode=1, cmd=cmd, output="IPv6地址配置验证失败")
                                    print(f"IPv6网关设置成功: {cmd}")
                                    gateway_success = True
                                    break  # 成功则跳出循环
                                except subprocess.CalledProcessError as e:
                                    print(f"IPv6网关设置命令格式{i+1}失败: {e}, 返回码: {e.returncode}")
                                    if hasattr(e, 'stdout') and e.stdout:
                                        print(f"命令输出: {e.stdout}")
                                    if hasattr(e, 'stderr') and e.stderr:
                                        print(f"错误输出: {e.stderr}")
                                    # 继续尝试下一个命令格式
                                except Exception as e:
                                    print(f"执行IPv6网关设置命令时出错: {str(e)}")
                                    # 继续尝试下一个命令格式
                            
                            # 如果所有IPv6网关设置命令都失败
                            if not gateway_success:
                                progress.setLabelText("正在尝试更多IPv6网关设置方法...")
                                progress.setValue(95)
                                print("所有IPv6网关设置命令格式都失败，尝试使用更多命令格式")
                                # 尝试更多的网关命令格式，但减少不必要的尝试，优先使用Windows 7兼容的命令
                                additional_gateway_cmds = [
                                    # 格式5: 使用不同的路由前缀 (Windows 7兼容)
                                    f'netsh interface ipv6 add route ::/0 interface="{nic_name}" nexthop={config["gateway_v6"]}',
                                    # 格式6: 使用引号包裹网关地址 (Windows 7兼容)
                                    f'netsh interface ipv6 add route ::/0 "{nic_name}" "{config["gateway_v6"]}"'
                                ]
                                
                                for i, cmd in enumerate(additional_gateway_cmds):
                                    try:
                                        print(f"尝试额外IPv6网关设置命令格式{i+1}: {cmd}")
                                        result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
                                        # 验证配置是否成功
                                        verify_cmd = f'netsh interface ipv6 show routes interface="{nic_name}"'
                                        verify_result = subprocess.run(verify_cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
                                        if not verify_result.stdout or config['gateway_v6'] not in verify_result.stdout:
                                            raise subprocess.CalledProcessError(returncode=1, cmd=cmd, output="IPv6网关配置验证失败")
                                        print(f"额外IPv6网关设置命令成功: {cmd}")
                                        gateway_success = True
                                        break  # 成功则跳出循环
                                    except subprocess.CalledProcessError as e:
                                        print(f"额外IPv6网关设置命令格式{i+1}失败: {e}, 返回码: {e.returncode}")
                                        if hasattr(e, 'stdout') and e.stdout:
                                            print(f"命令输出: {e.stdout}")
                                        if hasattr(e, 'stderr') and e.stderr:
                                            print(f"错误输出: {e.stderr}")
                                        # 继续尝试下一个命令格式
                                    except Exception as e:
                                        print(f"执行额外IPv6网关设置命令时出错: {str(e)}")
                                        # 继续尝试下一个命令格式
                        
                        # 如果IPv6地址设置失败，记录错误但不抛出异常，继续尝试设置DNS
                        if not success:
                            logger.error("所有IPv6地址设置命令都失败，但将继续尝试设置DNS")
                            error_msg = "IPv6地址设置失败，但将继续尝试设置DNS"
                            # 不抛出异常，让程序继续执行
                    
                    # 设置IPv6 DNS服务器
                    if config['dns_v6']:
                        dns_success = False
                        # 尝试清除DNS服务器的命令格式，减少不必要的尝试
                        clear_dns_cmds = [
                            # 格式1: 最基本的格式 (Windows 7兼容)
                            f'netsh interface ipv6 set dnsservers name="{nic_name}" source=static address=none',
                            # 格式2: 使用store=persistent参数 (Windows 7兼容)
                            f'netsh interface ipv6 set dnsservers name="{nic_name}" source=static address=none store=persistent',
                        ]
                        
                        # 尝试清除DNS服务器
                        clear_success = False
                        for i, cmd in enumerate(clear_dns_cmds):
                            try:
                                print(f"尝试清除IPv6 DNS服务器命令格式{i+1}: {cmd}")
                                subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
                                # 验证配置是否成功
                                verify_cmd = f'netsh interface ipv6 show dnsservers "{nic_name}"'
                                verify_result = subprocess.run(verify_cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
                                if verify_result.stdout and 'DNS servers configured through DHCP' not in verify_result.stdout:
                                    print(f"清除IPv6 DNS服务器成功: {cmd}")
                                    clear_success = True
                                    break  # 成功则跳出循环
                                else:
                                    raise subprocess.CalledProcessError(returncode=1, cmd=cmd, output="IPv6 DNS服务器清除验证失败")
                            except subprocess.CalledProcessError as e:
                                print(f"清除IPv6 DNS服务器命令格式{i+1}失败: {e}, 返回码: {e.returncode}")
                                if hasattr(e, 'stdout') and e.stdout:
                                    print(f"命令输出: {e.stdout}")
                                if hasattr(e, 'stderr') and e.stderr:
                                    print(f"错误输出: {e.stderr}")
                            except Exception as e:
                                print(f"执行清除IPv6 DNS服务器命令时出错: {str(e)}")
                        
                        # 如果清除失败，尝试更多命令格式，但减少不必要的尝试
                        if not clear_success:
                            progress.setLabelText("正在尝试更多IPv6 DNS清除方法...")
                            progress.setValue(80)
                            additional_clear_dns_cmds = [
                                # 格式3: 使用delete命令 (Windows 7兼容)
                                f'netsh interface ipv6 delete dnsservers "{nic_name}" all',
                                # 格式4: 使用不同的参数顺序 (Windows 7兼容)
                                f'netsh interface ipv6 set dnsservers "{nic_name}" address=none source=static'
                            ]
                            
                            for i, cmd in enumerate(additional_clear_dns_cmds):
                                try:
                                    print(f"尝试额外清除IPv6 DNS服务器命令格式{i+1}: {cmd}")
                                    subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
                                    # 验证配置是否成功
                                    verify_cmd = f'netsh interface ipv6 show dnsservers "{nic_name}"'
                                    verify_result = subprocess.run(verify_cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
                                    if verify_result.stdout and 'DNS servers configured through DHCP' not in verify_result.stdout:
                                        print(f"额外清除IPv6 DNS服务器命令成功: {cmd}")
                                        clear_success = True
                                        break  # 成功则跳出循环
                                    else:
                                        raise subprocess.CalledProcessError(returncode=1, cmd=cmd, output="IPv6 DNS服务器清除验证失败")
                                except subprocess.CalledProcessError as e:
                                    print(f"额外清除IPv6 DNS服务器命令格式{i+1}失败: {e}, 返回码: {e.returncode}")
                                    if hasattr(e, 'stdout') and e.stdout:
                                        print(f"命令输出: {e.stdout}")
                                    if hasattr(e, 'stderr') and e.stderr:
                                        print(f"错误输出: {e.stderr}")
                                    # 继续尝试下一个命令格式
                                except Exception as e:
                                    print(f"执行额外清除IPv6 DNS服务器命令时出错: {str(e)}")
                        
                        # 添加DNS服务器
                        dns_list = config['dns_v6'].split('\n')
                        dns_servers = [dns.strip() for dns in dns_list if dns.strip()]
                        
                        # 如果有DNS服务器需要设置
                        if dns_servers and len(dns_servers) > 0:
                            # 尝试使用netsh命令设置DNS服务器
                            netsh_success = False
                            
                            # 尝试设置第一个DNS服务器（主DNS）
                            try:
                                # 确保dns_servers列表不为空且至少有一个元素
                                if not dns_servers:
                                    raise IndexError("DNS服务器列表为空")
                                primary_dns = dns_servers[0]
                                # 减少主DNS服务器设置的命令尝试，优先使用Windows 7兼容的命令
                                primary_dns_cmds = [
                                    # 格式1: 不带register=primary参数 (Windows 7兼容)
                                    f'netsh interface ipv6 set dnsservers name="{nic_name}" source=static address={primary_dns}',
                                    # 格式2: 使用store=persistent参数 (Windows 7兼容)
                                    f'netsh interface ipv6 set dnsservers name="{nic_name}" source=static address={primary_dns} store=persistent'
                                ]
                                
                                # 尝试设置主DNS服务器
                                primary_success = False
                                for i, cmd in enumerate(primary_dns_cmds):
                                    try:
                                        print(f"尝试设置IPv6主DNS服务器命令格式{i+1}: {cmd}")
                                        result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
                                        # 验证配置是否成功
                                        verify_cmd = f'netsh interface ipv6 show dnsservers "{nic_name}"'
                                        verify_result = subprocess.run(verify_cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
                                        if not verify_result.stdout or primary_dns not in verify_result.stdout:
                                            raise subprocess.CalledProcessError(returncode=1, cmd=cmd, output="IPv6主DNS服务器配置验证失败")
                                        print(f"设置IPv6主DNS服务器成功: {primary_dns}")
                                        primary_success = True
                                        break  # 成功则跳出循环
                                    except subprocess.CalledProcessError as e:
                                        print(f"设置IPv6主DNS服务器命令格式{i+1}失败: {e}, 返回码: {e.returncode}")
                                        if hasattr(e, 'stdout') and e.stdout:
                                            print(f"命令输出: {e.stdout}")
                                        if hasattr(e, 'stderr') and e.stderr:
                                            print(f"错误输出: {e.stderr}")
                                    except Exception as e:
                                        print(f"执行设置IPv6主DNS服务器命令时出错: {str(e)}")
                                
                                # 如果设置主DNS成功，尝试设置备用DNS
                                if primary_success:
                                    try:
                                        if len(dns_servers) > 1:
                                            secondary_success = True  # 假设所有备用DNS都设置成功
                                            for i, dns in enumerate(dns_servers[1:], 1):
                                                # 减少备用DNS服务器设置的命令尝试，优先使用Windows 7兼容的命令
                                                secondary_dns_cmds = [
                                                    # 格式1: 使用index参数 (Windows 7兼容)
                                                    f'netsh interface ipv6 add dnsservers name="{nic_name}" address={dns} index={i+1}',
                                                    # 格式2: 使用store=persistent参数 (Windows 7兼容)
                                                    f'netsh interface ipv6 add dnsservers name="{nic_name}" address={dns} store=persistent'
                                                ]
                                        
                                                # 尝试设置备用DNS服务器
                                                dns_set = False
                                                for j, cmd in enumerate(secondary_dns_cmds):
                                                    try:
                                                        print(f"尝试设置IPv6备用DNS服务器{i}命令格式{j+1}: {cmd}")
                                                        result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
                                                        # 验证配置是否成功
                                                        verify_cmd = f'netsh interface ipv6 show dnsservers "{nic_name}"'
                                                        verify_result = subprocess.run(verify_cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
                                                        if not verify_result.stdout or dns not in verify_result.stdout:
                                                            raise subprocess.CalledProcessError(returncode=1, cmd=cmd, output=f"IPv6备用DNS服务器{i}配置验证失败")
                                                        print(f"设置IPv6备用DNS服务器{i}成功: {dns}")
                                                        dns_set = True
                                                        break  # 成功则跳出循环
                                                    except subprocess.CalledProcessError as e:
                                                        print(f"设置IPv6备用DNS服务器{i}命令格式{j+1}失败: {e}, 返回码: {e.returncode}")
                                                        if hasattr(e, 'stdout') and e.stdout:
                                                            print(f"命令输出: {e.stdout}")
                                                        if hasattr(e, 'stderr') and e.stderr:
                                                            print(f"错误输出: {e.stderr}")
                                                    except Exception as e:
                                                        print(f"执行设置IPv6备用DNS服务器{i}命令时出错: {str(e)}")
                                                
                                                # 如果所有命令格式都失败，标记备用DNS设置失败
                                                if not dns_set:
                                                    secondary_success = False
                                    
                                        # 如果主DNS和所有备用DNS都设置成功
                                        if secondary_success:
                                            netsh_success = True
                                        elif len(dns_servers) == 1:
                                            # 只有一个DNS服务器且设置成功
                                            netsh_success = True
                                    except Exception as e:
                                        print(f"设置IPv6备用DNS服务器时出错: {str(e)}")
                                        netsh_success = False
                            except Exception as e:
                                print(f"设置IPv6 DNS服务器时出错: {str(e)}")
                                netsh_success = False
                            
                            # 如果netsh命令设置DNS失败，尝试使用PowerShell
                            if not netsh_success:
                                try:
                                    # 确保dns_servers列表不为空
                                    if not dns_servers:
                                        raise IndexError("DNS服务器列表为空")
                                    # 构建PowerShell命令，逐个设置DNS服务器
                                    ps_cmd = f'powershell -Command "$dnsServers = @(); '
                                    for dns in dns_servers:
                                        ps_cmd += f"$dnsServers += '{dns}'; "
                                    ps_cmd += f'Set-DnsClientServerAddress -InterfaceAlias \"{nic_name}\" -ServerAddresses $dnsServers -AddressFamily IPv6"'
                                    subprocess.run(ps_cmd, shell=True, check=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
                                    # 验证配置是否成功
                                    verify_cmd = f'netsh interface ipv6 show dnsservers "{nic_name}"'
                                    verify_result = subprocess.run(verify_cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
                                    if not verify_result.stdout:
                                        raise subprocess.CalledProcessError(returncode=1, cmd=ps_cmd, output="PowerShell设置IPv6 DNS服务器验证失败 - 无输出")
                                    for dns in dns_servers:
                                        if dns not in verify_result.stdout:
                                            raise subprocess.CalledProcessError(returncode=1, cmd=ps_cmd, output="PowerShell设置IPv6 DNS服务器验证失败")
                                    print(f"使用PowerShell设置IPv6 DNS服务器成功: {ps_cmd}")
                                    dns_success = True
                                except subprocess.CalledProcessError as e:
                                    print(f"PowerShell设置IPv6 DNS服务器失败: {e}")
                                    if hasattr(e, 'stdout') and e.stdout:
                                        print(f"命令输出: {e.stdout}")
                                    if hasattr(e, 'stderr') and e.stderr:
                                        print(f"错误输出: {e.stderr}")
                                    # 记录错误但不中断执行
                                    logger.error(f"PowerShell设置IPv6 DNS服务器失败: {e}")
                                    error_msg = f"PowerShell设置IPv6 DNS服务器失败，但程序将继续执行"
                                except Exception as e:
                                    print(f"执行PowerShell设置IPv6 DNS服务器命令时出错: {str(e)}")
                                    # 记录错误但不中断执行
                                    logger.error(f"执行PowerShell设置IPv6 DNS服务器命令时出错: {str(e)}")
                                    error_msg = f"执行PowerShell设置IPv6 DNS服务器命令时出错，但程序将继续执行"
                            else:
                                dns_success = True
                success = True
        except subprocess.CalledProcessError as e:
            error_msg = f"执行命令失败: {str(e)}, 返回码: {e.returncode}"
            print(f"应用IP配置出错: {error_msg}")
            if hasattr(e, 'output') and e.output:
                print(f"命令输出: {e.output}")
            if hasattr(e, 'stderr') and e.stderr:
                print(f"错误输出: {e.stderr}")
            # 记录错误但不将success设为False，让调用者决定如何处理
            logger.error(f"应用IP配置出错: {error_msg}")
            # 如果是IPv6配置，可能部分成功，不将整个操作标记为失败
            if not self.is_ipv4:
                success = True
        except Exception as e:
            error_msg = f"应用配置时出错: {str(e)}"
            print(f"应用IP配置出错: {error_msg}")
            import traceback
            trace_info = traceback.format_exc()
            print(f"详细错误信息: {trace_info}")
            logger.error(f"应用IP配置详细错误: {trace_info}")
            # 如果是IPv6配置，可能部分成功，不将整个操作标记为失败
            if not self.is_ipv4:
                success = True
        finally:
            # 关闭进度对话框
            progress.setValue(100)
            
        return success, error_msg

# 主窗口
class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('一键配置电脑IP工具')
        self.resize(800, 600)
        self.layout = QVBoxLayout(self)
        
        # 创建标签控件
        self.tabs = QTabWidget()
        self.layout.addWidget(self.tabs)
        
        # 创建标签页
        self.main_tab = QWidget()
        self.ping_tab = QWidget()
        self.log_tab = QWidget()
        
        # 添加标签页到标签控件
        self.tabs.addTab(self.main_tab, '主界面')
        self.tabs.addTab(self.ping_tab, 'Ping测试')
        self.tabs.addTab(self.log_tab, '运行日志')
        
        # 初始化标签页
        self.init_main_tab()
        self.init_ping_tab()
        self.init_log_tab()
    
    def init_main_tab(self):
        """初始化主界面标签页"""
        # 创建主界面布局
        main_layout = QVBoxLayout()
        
        # 网卡选择区域
        nic_layout = QHBoxLayout()
        nic_label = QLabel("选择网卡:")
        self.nic_combo = QComboBox()
        self.nic_combo.setMinimumWidth(300)
        self.refresh_btn = QPushButton("刷新")
        
        nic_layout.addWidget(nic_label)
        nic_layout.addWidget(self.nic_combo)
        nic_layout.addWidget(self.refresh_btn)
        nic_layout.addStretch()
        
        # 加载网卡列表
        self.load_nics()
        
        # 连接信号
        self.nic_combo.currentIndexChanged.connect(self.update_ip_info)
        self.refresh_btn.clicked.connect(self.load_nics)
        
        # 添加网卡选择区域到主布局
        main_layout.addLayout(nic_layout)
        
        # IP信息显示区域
        ip_layout = QHBoxLayout()
        
        # 左侧IPv4信息
        ipv4_group = QGroupBox("IPv4配置")
        ipv4_layout = QGridLayout()
        
        # IPv4地址
        ipv4_layout.addWidget(QLabel("IPv4地址:"), 0, 0)
        self.ipv4_value = QLabel("未知")
        ipv4_layout.addWidget(self.ipv4_value, 0, 1)
        
        # IPv4子网掩码
        ipv4_layout.addWidget(QLabel("子网掩码:"), 1, 0)
        self.mask_value = QLabel("未知")
        ipv4_layout.addWidget(self.mask_value, 1, 1)
        
        # IPv4默认网关
        ipv4_layout.addWidget(QLabel("默认网关:"), 2, 0)
        self.gateway_v4_value = QLabel("未知")
        ipv4_layout.addWidget(self.gateway_v4_value, 2, 1)
        
        # IPv4 DNS
        ipv4_layout.addWidget(QLabel("主DNS服务器(IPv4):"), 3, 0)
        self.dns_v4_primary_value = QLabel("未知")
        ipv4_layout.addWidget(self.dns_v4_primary_value, 3, 1)
        ipv4_layout.addWidget(QLabel("备DNS服务器(IPv4):"), 4, 0)
        self.dns_v4_secondary_value = QLabel("未知")
        ipv4_layout.addWidget(self.dns_v4_secondary_value, 4, 1)
        
        ipv4_group.setLayout(ipv4_layout)
        
        # 右侧IPv6信息
        ipv6_group = QGroupBox("IPv6配置")
        ipv6_layout = QGridLayout()
        
        # IPv6地址
        ipv6_layout.addWidget(QLabel("IPv6地址:"), 0, 0)
        self.ipv6_value = QLabel("未知")
        ipv6_layout.addWidget(self.ipv6_value, 0, 1)
        
        # IPv6前缀长度
        ipv6_layout.addWidget(QLabel("前缀长度:"), 1, 0)
        self.mask_v6_value = QLabel("未知")
        ipv6_layout.addWidget(self.mask_v6_value, 1, 1)
        
        # IPv6默认网关
        ipv6_layout.addWidget(QLabel("默认网关:"), 2, 0)
        self.gateway_v6_value = QLabel("未知")
        ipv6_layout.addWidget(self.gateway_v6_value, 2, 1)
        
        # IPv6 DNS
        ipv6_layout.addWidget(QLabel("主DNS服务器(IPv6):"), 3, 0)
        self.dns_v6_primary_value = QLabel("未知")
        ipv6_layout.addWidget(self.dns_v6_primary_value, 3, 1)
        ipv6_layout.addWidget(QLabel("备DNS服务器(IPv6):"), 4, 0)
        self.dns_v6_secondary_value = QLabel("未知")
        ipv6_layout.addWidget(self.dns_v6_secondary_value, 4, 1)
        
        ipv6_group.setLayout(ipv6_layout)
        
        # 添加IPv4和IPv6信息到IP布局
        ip_layout.addWidget(ipv4_group)
        ip_layout.addWidget(ipv6_group)
        
        # 添加IP信息区域到主布局
        main_layout.addLayout(ip_layout)
        
        # 底部信息区域
        bottom_layout = QHBoxLayout()
        
        # MAC地址
        bottom_layout.addWidget(QLabel("MAC地址:"))
        self.mac_value = QLabel("未知")
        bottom_layout.addWidget(self.mac_value)
        
        bottom_layout.addSpacing(20)
        
        # DHCP状态
        bottom_layout.addWidget(QLabel("DHCP状态:"))
        self.dhcp_value = QLabel("未知")
        bottom_layout.addWidget(self.dhcp_value)
        
        bottom_layout.addStretch()
        
        # 操作按钮
        self.change_ipv4_btn = QPushButton("更改IPv4配置")
        self.change_ipv6_btn = QPushButton("更改IPv6配置")
        
        bottom_layout.addWidget(self.change_ipv4_btn)
        bottom_layout.addWidget(self.change_ipv6_btn)
        
        # 连接按钮信号
        self.change_ipv4_btn.clicked.connect(self.change_ipv4_config)
        self.change_ipv6_btn.clicked.connect(self.change_ipv6_config)
        
        # 添加底部区域到主布局
        main_layout.addLayout(bottom_layout)
        
        # 设置主标签页的布局
        self.main_tab.setLayout(main_layout)
        
        # 初始化更新IP信息
        if self.nic_combo.count() > 0:
            self.update_ip_info()
            
    def refresh_nic_info(self):
        """刷新网卡信息"""
        # 调用load_nics方法刷新网卡列表
        self.load_nics()
        
    def load_nics(self):
        """加载网卡列表"""
        self.nic_combo.clear()
        
        # 获取网卡信息
        nics = get_ethernet_info()
        
        if not nics:
            self.nic_combo.addItem("未检测到以太网卡")
            return
        
        # 添加网卡到下拉框
        for nic_name, display_name in nics:
            self.nic_combo.addItem(display_name, nic_name)
    
    def init_ping_tab(self):
        vbox = QVBoxLayout(self.ping_tab)
        
        # 协议选择
        protocol_group = QGroupBox('协议')
        protocol_layout = QHBoxLayout(protocol_group)
        
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(['IPv4', 'IPv6'])
        protocol_layout.addWidget(self.protocol_combo)
        
        vbox.addWidget(protocol_group)
        
        # 目标选择
        target_group = QGroupBox('目标')
        target_layout = QVBoxLayout(target_group)
        
        self.target_combo = QComboBox()
        self.target_combo.addItems(['网关', 'DNS', '自定义'])
        self.target_combo.currentIndexChanged.connect(self.toggle_custom_target)
        target_layout.addWidget(self.target_combo)
        
        self.custom_target_input = QLineEdit()
        self.custom_target_input.setPlaceholderText('请输入IP地址或域名')
        self.custom_target_input.setEnabled(False)
        target_layout.addWidget(self.custom_target_input)
        
        vbox.addWidget(target_group)
        
        # 参数设置
        param_group = QGroupBox('参数设置')
        param_layout = QGridLayout(param_group)
        
        self.count_label = QLabel('包个数:')
        self.count_spin = QSpinBox()
        self.count_spin.setRange(1, 100)
        self.count_spin.setValue(4)
        param_layout.addWidget(self.count_label, 0, 0)
        param_layout.addWidget(self.count_spin, 0, 1)
        
        self.size_label = QLabel('包大小:')
        self.size_spin = QSpinBox()
        self.size_spin.setRange(32, 65500)
        self.size_spin.setValue(32)
        param_layout.addWidget(self.size_label, 1, 0)
        param_layout.addWidget(self.size_spin, 1, 1)
        
        vbox.addWidget(param_group)
        
        # 结果显示
        result_group = QGroupBox('测试结果')
        result_layout = QVBoxLayout(result_group)
        
        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)
        result_layout.addWidget(self.result_text)
        
        vbox.addWidget(result_group)
        
        # 操作按钮
        btn_layout = QHBoxLayout()
        
        self.start_btn = QPushButton('开始测试')
        self.start_btn.clicked.connect(self.start_ping)
        btn_layout.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton('停止测试')
        self.stop_btn.clicked.connect(self.stop_ping)
        self.stop_btn.setEnabled(False)
        btn_layout.addWidget(self.stop_btn)
        
        vbox.addLayout(btn_layout)

    def refresh_nic_info(self):
        # 刷新网卡列表
        current_text = self.nic_combo.currentText()
        self.nic_combo.clear()
        self.nic_combo.addItems(get_ethernet_info())
        
        # 尝试恢复之前选择的网卡
        index = self.nic_combo.findText(current_text)
        if index >= 0:
            self.nic_combo.setCurrentIndex(index)
        
        # 更新IP信息
        self.update_ip_info()
    
    def update_ip_info(self):
        """更新IP信息"""
        # 如果没有选择网卡，则显示未知
        if self.nic_combo.count() == 0 or self.nic_combo.currentIndex() == -1:
            self.ipv4_value.setText("未知")
            self.ipv6_value.setText("未知")
            self.mask_value.setText("未知")
            self.mask_v6_value.setText("未知")
            self.gateway_v4_value.setText("未知")
            self.gateway_v6_value.setText("未知")
            self.dns_v4_primary_value.setText("")
            self.dns_v4_secondary_value.setText("")
            self.dns_v6_primary_value.setText("")
            self.dns_v6_secondary_value.setText("")
            self.mac_value.setText("未知")
            self.dhcp_value.setText("无法获取")
            return

        # 获取当前选择的网卡名称
        nic_name = self.nic_combo.currentData()
        if not nic_name:
            return

        # 更新IP信息
        ip_info = parse_ip_config(get_ip_config(nic_name))
        print(f"解析到的IP信息: {ip_info}")

        # 更新UI显示
        self.ipv4_value.setText(ip_info['IPv4'])
        self.ipv6_value.setText(ip_info['IPv6'])
        
        self.mask_value.setText(ip_info['Mask_v4'])
        self.mask_v6_value.setText(ip_info['Mask_v6'])
        self.gateway_v4_value.setText(ip_info['Gateway_v4'])
        self.gateway_v6_value.setText(ip_info['Gateway_v6'])
        self.mac_value.setText(ip_info['MAC'])
        self.dhcp_value.setText("是" if ip_info['DHCP'] else "否")

        # 处理DNS服务器信息
        dns_v4_list = ip_info['DNS_v4'].split('\n') if ip_info['DNS_v4'] else []
        if len(dns_v4_list) > 0:
            self.dns_v4_primary_value.setText(dns_v4_list[0])
            print(f"设置IPv4主DNS: {dns_v4_list[0]}")
        else:
            self.dns_v4_primary_value.setText("")
        
        if len(dns_v4_list) > 1:
            self.dns_v4_secondary_value.setText(dns_v4_list[1])
            print(f"设置IPv4备DNS: {dns_v4_list[1]}")
        else:
            # 当备用DNS为空时，显示为空白
            self.dns_v4_secondary_value.setText("")

        dns_v6_list = ip_info['DNS_v6'].split('\n') if ip_info['DNS_v6'] else []
        if len(dns_v6_list) > 0:
            self.dns_v6_primary_value.setText(dns_v6_list[0])
            print(f"设置IPv6主DNS: {dns_v6_list[0]}")
        else:
            self.dns_v6_primary_value.setText("")
        
        if len(dns_v6_list) > 1:
            self.dns_v6_secondary_value.setText(dns_v6_list[1])
            print(f"设置IPv6备DNS: {dns_v6_list[1]}")
        else:
            # 当备用DNS为空时，显示为空白
            self.dns_v6_secondary_value.setText("")

        # IPv6默认网关
        if ip_info['Gateway_v6'] != '未知':
            self.gateway_v6_value.setText(ip_info['Gateway_v6'])
        else:
            self.gateway_v6_value.setText('无')
        
        # MAC地址和DHCP状态
        self.mac_value.setText(ip_info['MAC'])
        self.dhcp_value.setText('自动分配' if ip_info['DHCP'] else '手动分配')
        
        # 打印调试信息
        print(f"更新IP信息: {ip_info}")
        print(f"IPv4: {ip_info['IPv4']}")
        print(f"IPv6: {ip_info['IPv6']}")
        print(f"IPv4子网掩码: {ip_info['Mask_v4']}")
        print(f"IPv6前缀长度: {ip_info['Mask_v6']}")
        print(f"IPv4网关: {ip_info['Gateway_v4']}")
        print(f"IPv6网关: {ip_info['Gateway_v6']}")
        print(f"IPv4 DNS: {ip_info['DNS_v4']}")
        print(f"IPv6 DNS: {ip_info['DNS_v6']}")
        print(f"MAC地址: {ip_info['MAC']}")
        print(f"DHCP状态: {ip_info['DHCP']}")
        
        # 根据DHCP状态设置输入框是否可编辑
        # self.toggle_inputs(not ip_info['DHCP'])  # 注释掉这行，因为MainWindow没有toggle_inputs方法
    
    def change_ipv4_config(self):
        # 获取当前IP信息
        nic_name = self.nic_combo.currentText()
        if '未检测到以太网卡' in nic_name or '获取网卡信息出错' in nic_name:
            QMessageBox.warning(self, '警告', '无法获取网卡信息，无法更改配置')
            return
        
        # 获取网卡名称（不包含MAC地址部分）
        nic_name = self.nic_combo.currentData()
        if not nic_name:
            QMessageBox.warning(self, '警告', '无法获取网卡名称，无法更改配置')
            return
        
        config_text = get_ip_config(nic_name)
        ip_info = parse_ip_config(config_text)
        
        # 打开配置对话框
        dialog = IPConfigDialog(self, ip_info, True)
        if dialog.exec_():
            # 检查管理员权限
            if not is_admin():
                reply = QMessageBox.question(self, '需要管理员权限', 
                                           '更改IP配置需要管理员权限，是否以管理员身份重新启动程序？',
                                           QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
                if reply == QMessageBox.Yes:
                    run_as_admin()
                return
            
            # 应用配置
            success, error_msg = dialog.apply_config(nic_name)
            
            if success:
                QMessageBox.information(self, '成功', 'IP配置已成功更改')
            else:
                QMessageBox.critical(self, '错误', f'更改IP配置失败: {error_msg}')
            
            # 刷新IP信息
            self.update_ip_info()
    
    def change_ipv6_config(self):
        # 获取当前IP信息
        nic_name = self.nic_combo.currentText()
        if '未检测到以太网卡' in nic_name or '获取网卡信息出错' in nic_name:
            QMessageBox.warning(self, '警告', '无法获取网卡信息，无法更改配置')
            return
        
        # 获取网卡名称（不包含MAC地址部分）
        nic_name = self.nic_combo.currentData()
        if not nic_name:
            QMessageBox.warning(self, '警告', '无法获取网卡名称，无法更改配置')
            return
        
        config_text = get_ip_config(nic_name)
        ip_info = parse_ip_config(config_text)
        
        # 打开配置对话框
        dialog = IPConfigDialog(self, ip_info, False)
        if dialog.exec_():
            # 检查管理员权限
            if not is_admin():
                reply = QMessageBox.question(self, '需要管理员权限', 
                                           '更改IP配置需要管理员权限，是否以管理员身份重新启动程序？',
                                           QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
                if reply == QMessageBox.Yes:
                    run_as_admin()
                return
            
            # 应用配置
            try:
                success, error_msg = dialog.apply_config(nic_name)
                
                if success:
                    QMessageBox.information(self, '成功', 'IP配置已成功更改')
                else:
                    QMessageBox.warning(self, '警告', f'IPv6配置可能部分失败: {error_msg}\n\n请检查网络设置是否生效。')
            except Exception as e:
                import traceback
                error_details = traceback.format_exc()
                logger.error(f"应用IPv6配置时出错: {str(e)}\n{error_details}")
                QMessageBox.critical(self, '错误', f'应用IPv6配置时出错: {str(e)}')
            
            # 刷新IP信息
            self.update_ip_info()
    
    def toggle_custom_target(self, index):
        """切换自定义目标输入框的启用状态"""
        self.custom_target_input.setEnabled(index == 2)  # 2表示'自定义'选项
        
    def init_log_tab(self):
        """初始化运行日志标签页"""
        # 创建布局
        layout = QVBoxLayout(self.log_tab)
        
        # 日志显示区域
        log_group = QGroupBox("程序运行日志")
        log_layout = QVBoxLayout()
        
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        # 设置等宽字体，使日志更易读
        font = QFont("Courier New", 9)
        self.log_text.setFont(font)
        log_layout.addWidget(self.log_text)
        
        log_group.setLayout(log_layout)
        layout.addWidget(log_group)
        
        # 底部按钮区域
        button_layout = QHBoxLayout()
        
        self.refresh_log_button = QPushButton("刷新日志")
        self.clear_log_button = QPushButton("清空日志")
        
        button_layout.addStretch()
        button_layout.addWidget(self.refresh_log_button)
        button_layout.addWidget(self.clear_log_button)
        button_layout.addStretch()
        
        layout.addLayout(button_layout)
        
        # 连接信号
        self.refresh_log_button.clicked.connect(self.refresh_log)
        self.clear_log_button.clicked.connect(self.clear_log)
        
        # 初始加载日志
        self.refresh_log()
        
        # 设置定时器，每5秒自动刷新一次日志
        from PyQt5.QtCore import QTimer
        self.log_timer = QTimer(self)
        self.log_timer.timeout.connect(self.refresh_log)
        self.log_timer.start(5000)  # 5000毫秒 = 5秒
        
    def refresh_log(self):
        """刷新日志内容"""
        try:
            # 获取日志文件路径
            log_file_path = os.path.join(os.path.dirname(__file__), 'debug_ip_config.log')
            
            # 始终从内存处理器获取日志，确保显示所有日志内容
            from log_config import memory_handler
            log_content = memory_handler.get_logs()
            
            # 如果内存日志为空，尝试从文件读取（兼容性考虑）
            if not log_content.strip() and os.path.exists(log_file_path):
                try:
                    # 读取日志文件内容 - 使用gbk编码与日志文件写入编码一致
                    with open(log_file_path, 'r', encoding='gbk', errors='replace') as f:
                        file_log_content = f.read()
                    if file_log_content.strip():
                        log_content = file_log_content
                except Exception:
                    # 如果读取文件失败，使用空内存日志
                    pass
            
            # 如果没有任何日志内容，显示提示信息
            if not log_content.strip():
                log_content = "--- 暂无日志内容 ---"
            
            # 更新日志显示
            self.log_text.setText(log_content)
            
            # 滚动到底部
            self.log_text.moveCursor(self.log_text.textCursor().End)
        except Exception as e:
            self.log_text.setText(f"刷新日志时出错: {str(e)}")
    
    def clear_log(self):
        """清空日志内容"""
        try:
            # 清空日志显示
            self.log_text.clear()
            
            # 获取日志文件路径
            log_file_path = os.path.join(os.path.dirname(__file__), 'debug_ip_config.log')
            
            # 清空内存日志
            from log_config import memory_handler
            memory_handler.log_buffer = io.StringIO()
            
            # 检查文件是否存在
            if os.path.exists(log_file_path):
                try:
                    # 清空日志文件内容 - 使用gbk编码与日志文件写入编码一致
                    with open(log_file_path, 'w', encoding='gbk') as f:
                        f.write("--- 日志已清空 ---\n")
                except Exception as file_error:
                    # 如果清空文件失败，记录到内存日志
                    from log_config import logger
                    logger.warning(f"清空日志文件失败: {str(file_error)}")
            
            # 重新初始化日志
            from log_config import logger
            logger.info("--- 日志重新开始 ---")
        except Exception as e:
            self.log_text.setText(f"清空日志文件时出错: {str(e)}")
            
            # 尝试重新加载日志
            self.refresh_log()
    
    def start_ping(self):
        """开始Ping测试"""
        # 获取当前选择的网卡
        nic_name = self.nic_combo.currentText()
        if not nic_name or '未检测到' in nic_name or '获取网卡信息出错' in nic_name:
            QMessageBox.warning(self, '警告', '请先选择有效的网卡')
            return
        
        # 获取目标地址
        target_type = self.target_combo.currentText()
        target = ''
        
        if target_type == '网关':
            # 根据协议选择IPv4或IPv6网关
            protocol = self.protocol_combo.currentText()
            if protocol == 'IPv4':
                target = self.gateway_v4_value.text()
            else:  # IPv6
                target = self.gateway_v6_value.text()
        elif target_type == 'DNS':
            # 根据协议选择IPv4或IPv6 DNS
            protocol = self.protocol_combo.currentText()
            if protocol == 'IPv4':
                dns_text = self.dns_v4_primary_value.text()
                # 如果有多个DNS，取第一个
                if ',' in dns_text:
                    target = dns_text.split(',')[0].strip()
                else:
                    target = dns_text
            else:  # IPv6
                dns_text = self.dns_v6_primary_value.text()
                # 如果有多个DNS，取第一个
                if ',' in dns_text:
                    target = dns_text.split(',')[0].strip()
                else:
                    target = dns_text
        else:  # 自定义
            target = self.custom_target_input.text()
        
        if not target or target == '无' or target == '未知':
            QMessageBox.warning(self, '警告', '无法获取目标地址，请检查网络配置或输入自定义地址')
            return
        
        # 获取参数
        count = self.count_spin.value()
        size = self.size_spin.value()
        protocol = self.protocol_combo.currentText()
        
        # 清空结果显示
        self.result_text.clear()
        self.result_text.append(f"开始Ping测试: {target}\n")
        
        # 创建并启动Ping线程
        self.ping_thread = PingThread(target, count, size, protocol)
        self.ping_thread.update_signal.connect(self.update_ping_result)
        self.ping_thread.finished.connect(self.on_ping_finished)
        self.ping_thread.start()
        
        # 更新按钮状态
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
    
    def stop_ping(self):
        """停止Ping测试"""
        if hasattr(self, 'ping_thread') and self.ping_thread.isRunning():
            self.ping_thread.terminate()
            self.ping_thread.wait()
            self.result_text.append("\nPing测试已停止")
            
            # 更新按钮状态
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
    
    def update_ping_result(self, text):
        """更新Ping测试结果"""
        self.result_text.append(text)
    
    def on_ping_finished(self):
        """Ping测试完成回调"""
        self.result_text.append("\nPing测试已完成")
        
        # 更新按钮状态
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

# 重定向标准输出和标准错误到日志文件，避免显示外部CMD窗口
def redirect_output_to_log():
    """重定向标准输出和标准错误到日志文件"""
    class LogRedirector:
        def __init__(self, logger_func):
            self.logger_func = logger_func
            self.buffer = ''
        
        def write(self, text):
            if not text:  # 忽略空文本
                return
            
            self.buffer += text
            if '\n' in self.buffer:
                lines = self.buffer.split('\n')
                for line in lines[:-1]:
                    if line.strip():  # 只记录非空行
                        self.logger_func(line.rstrip())
                self.buffer = lines[-1]
        
        def flush(self):
            if self.buffer.strip():  # 只记录非空行
                self.logger_func(self.buffer.rstrip())
            self.buffer = ''
            
        # 确保对象可以被用作文件对象
        def fileno(self):
            return -1
    
    # 记录重定向开始的日志
    from log_config import logger
    logger.info("开始重定向标准输出和标准错误到日志系统")
    
    # 重定向标准输出到日志
    sys.stdout = LogRedirector(log_info)
    # 重定向标准错误到日志
    sys.stderr = LogRedirector(log_error)
    
    # 记录重定向完成的日志
    logger.info("标准输出和标准错误已重定向到日志系统")

if __name__ == '__main__':
    try:
        # 记录程序启动日志
        logger.info("程序开始启动")
        
        # 重定向输出到日志文件，避免显示外部CMD窗口
        redirect_output_to_log()
        
        # 检查管理员权限，如果没有则直接以管理员权限重启
        if not is_admin():
            logger.info("程序需要管理员权限，正在尝试以管理员身份重启...")
            run_as_admin()
            sys.exit(0)
        
        # 记录程序初始化信息
        logger.info(f"操作系统: {os.name}")
        logger.info(f"Python版本: {sys.version}")
        logger.info("正在初始化GUI界面...")
        
        # 初始化应用程序
        app = QApplication(sys.argv)
        logger.info("GUI界面初始化完成")
        
        # 创建并显示主窗口
        window = MainWindow()
        window.show()
        logger.info("主窗口已显示")
        
        # 进入应用程序主循环
        sys.exit(app.exec_())
    except Exception as e:
        logger.error(f"程序启动错误: {str(e)}")
        logger.error(traceback.format_exc())