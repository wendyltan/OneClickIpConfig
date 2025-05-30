import subprocess
import re
import os
from subprocess import CREATE_NO_WINDOW

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
                    if next_adapter_pos != -1:
                        end_pos = next_adapter_pos
                    else:
                        end_pos = len(output)
                    section = output[start_pos:end_pos].strip()
                
                return section
            else:
                print(f"未找到网卡 {pure_nic_name} 的信息段落")
                return f"未找到网卡 {pure_nic_name} 的信息"
        else:
            print(f"未找到网卡 {pure_nic_name} 的标记")
            return f"未找到网卡 {pure_nic_name} 的信息"
    except Exception as e:
        print(f"获取IP配置信息出错: {e}")
        return f"获取IP配置信息出错: {str(e)}"

# 获取DNS服务器信息
def get_dns_servers(nic_name):
    """使用nslookup获取DNS服务器信息"""
    ipv4_dns_servers = []
    ipv6_dns_servers = []
    
    try:
        # 使用netsh命令获取IPv4 DNS服务器信息
        ipv4_cmd = f'netsh interface ipv4 show dnsservers "{nic_name}"'
        ipv4_result = subprocess.run(ipv4_cmd, shell=True, capture_output=True, text=True, encoding='gbk', errors='ignore', creationflags=CREATE_NO_WINDOW)
        ipv4_output = ipv4_result.stdout
        
        # 打印原始输出用于调试
        print(f"IPv4 DNS服务器信息:\n{ipv4_output}")
        
        # 解析IPv4 DNS服务器地址
        for line in ipv4_output.splitlines():
            # 查找包含IPv4地址格式的行
            ipv4_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
            if ipv4_match:
                ipv4_dns = ipv4_match.group(1)
                # 过滤掉127.0.2.2这个特殊IP地址，它可能是系统自动设置的默认值
                if ipv4_dns not in ipv4_dns_servers and ipv4_dns != '127.0.2.2':
                    ipv4_dns_servers.append(ipv4_dns)
        
        # 使用netsh命令获取IPv6 DNS服务器信息
        ipv6_cmd = f'netsh interface ipv6 show dnsservers "{nic_name}"'
        ipv6_result = subprocess.run(ipv6_cmd, shell=True, capture_output=True, text=True, encoding='gbk', errors='ignore', creationflags=CREATE_NO_WINDOW)
        ipv6_output = ipv6_result.stdout
        
        # 打印原始输出用于调试
        print(f"IPv6 DNS服务器信息:\n{ipv6_output}")
        
        # 解析IPv6 DNS服务器地址
        for line in ipv6_output.splitlines():
            # 查找包含IPv6地址格式的行
            ipv6_match = re.search(r'([0-9a-fA-F:]+:[0-9a-fA-F:]+)', line)
            if ipv6_match:
                ipv6_dns = ipv6_match.group(1)
                # 过滤掉可能是系统自动设置的特殊IPv6地址
                if ipv6_dns not in ipv6_dns_servers and not ipv6_dns.startswith('::'):
                    ipv6_dns_servers.append(ipv6_dns)
        
        return ipv4_dns_servers, ipv6_dns_servers
    except Exception as e:
        print(f"获取DNS服务器信息出错: {e}")
        return [], []

# 解析IP配置信息
def parse_ip_config(config_text):
    """解析ipconfig输出的配置信息"""
    info = {
        'IPv4': '未知',
        'IPv6': '未知',
        'Mask_v4': '未知',
        'Mask_v6': '未知',
        'Gateway_v4': '未知',
        'Gateway_v6': '未知',
        'DNS_v4': '',
        'DNS_v6': '',
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
    
    # 逐行解析配置信息
    for line in config_text.splitlines():
        line = line.strip()
        
        # 检查是否包含DHCP信息
        if 'DHCP 已启用' in line or 'DHCP Enabled' in line:
            if '是' in line or 'Yes' in line:
                info['DHCP'] = True
        
        # 检查是否包含IPv4地址
        ipv4_match = re.search(r'IPv4.+?:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
        if ipv4_match:
            info['IPv4'] = ipv4_match.group(1)
        
        # 检查是否包含IPv6地址
        ipv6_match = re.search(r'IPv6.+?:\s*([0-9a-fA-F:]+:[0-9a-fA-F:]+)', line)
        if ipv6_match:
            info['IPv6'] = ipv6_match.group(1)
        
        # 检查是否包含子网掩码
        mask_match = re.search(r'子网掩码|Subnet Mask.+?:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
        if mask_match:
            info['Mask_v4'] = mask_match.group(1)
        
        # 检查是否包含IPv6前缀长度
        prefix_match = re.search(r'前缀长度|Prefix Length.+?:\s*(\d+)', line)
        if prefix_match:
            info['Mask_v6'] = prefix_match.group(1)
        
        # 检查是否包含MAC地址
        mac_match = re.search(r'物理地址|Physical Address.+?:\s*([0-9A-F-]+)', line)
        if mac_match:
            info['MAC'] = mac_match.group(1)
        
        # 检查是否包含默认网关
        gateway_match = re.search(r'默认网关|Default Gateway.+?:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
        if gateway_match:
            info['Gateway_v4'] = gateway_match.group(1)
        
        # 检查是否包含IPv6默认网关
        gateway_v6_match = re.search(r'默认网关|Default Gateway.+?:\s*([0-9a-fA-F:]+:[0-9a-fA-F:]+)', line)
        if gateway_v6_match:
            info['Gateway_v6'] = gateway_v6_match.group(1)
    
    return info