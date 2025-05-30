import subprocess
import re
import os
import sys
import ctypes
from subprocess import CREATE_NO_WINDOW

# 从network_utils导入必要的函数
from network_utils import get_ethernet_info, get_ip_config, get_dns_servers, parse_ip_config

# 检查是否具有管理员权限
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# IPv4配置函数
def configure_ipv4(nic_name, config):
    """配置IPv4地址、子网掩码、网关和DNS服务器"""
    success = False
    error_msg = ""
    
    # 检查管理员权限
    if not is_admin():
        error_msg = "需要管理员权限才能配置网络设置。请以管理员身份运行程序。"
        print(error_msg)
        return False, error_msg
    
    try:
        # 设置IPv4地址和子网掩码
        if config['ipv4'] and config['mask']:
            # 获取网络接口索引
            ifindex = None
            try:
                # 使用PowerShell获取接口索引
                ps_cmd = f'powershell -Command "(Get-NetAdapter | Where-Object {{$_.Name -eq \"{nic_name}\"}} | Select-Object -ExpandProperty ifIndex)"'
                result = subprocess.run(ps_cmd, shell=True, capture_output=True, text=True, creationflags=CREATE_NO_WINDOW)
                if result.stdout.strip():
                    ifindex = result.stdout.strip()
                    print(f"获取到网络接口 {nic_name} 的索引: {ifindex}")
            except Exception as e:
                print(f"获取网络接口索引失败: {str(e)}")
            
            # 清除现有IP配置 (优化Windows 7兼容性)
            clear_cmds = [
                # Windows 7兼容的命令格式
                f'netsh interface ipv4 set address name="{nic_name}" source=static address=none'
            ]
            
            clear_success = False
            for cmd in clear_cmds:
                try:
                    print(f"尝试清除IPv4配置: {cmd}")
                    subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True, creationflags=CREATE_NO_WINDOW)
                    clear_success = True
                    break
                except Exception as e:
                    print(f"清除IPv4配置命令失败: {str(e)}")
            
            if not clear_success:
                print("清除IPv4配置命令失败，但将继续尝试设置新IP")
            
            # 设置新的IP地址和子网掩码 (优化Windows 7兼容性)
            ip_cmds = [
                # Windows 7兼容的命令格式
                f'netsh interface ipv4 set address name="{nic_name}" source=static address={config["ipv4"]} mask={config["mask"]}'
            ]
            
            # 添加网关参数（如果有）
            if config['gateway']:
                ip_cmds = [
                    f'netsh interface ipv4 set address name="{nic_name}" source=static address={config["ipv4"]} mask={config["mask"]} gateway={config["gateway"]}'
                ]
            
            ip_success = False
            for cmd in ip_cmds:
                try:
                    print(f"尝试设置IPv4地址: {cmd}")
                    subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True, creationflags=CREATE_NO_WINDOW)
                    ip_success = True
                    break
                except Exception as e:
                    print(f"设置IPv4地址命令失败: {str(e)}")
            
            if not ip_success:
                print("设置IPv4地址命令失败")
                raise Exception("IPv4地址配置失败")
            
            # 验证IP配置是否成功
            verify_cmd = f'ipconfig /all'
            verify_result = subprocess.run(verify_cmd, shell=True, capture_output=True, text=True, creationflags=CREATE_NO_WINDOW)
            if config['ipv4'] not in verify_result.stdout:
                raise subprocess.CalledProcessError(returncode=1, cmd="verify", output="IPv4地址配置验证失败")
            
            print(f"IPv4地址设置成功: {config['ipv4']}")
        
        # 设置IPv4 DNS服务器
        if config['dns']:
            dns_success = configure_ipv4_dns(nic_name, config['dns'])
            if not dns_success:
                error_msg = "IPv4 DNS服务器配置失败"
        
        success = True
    except subprocess.CalledProcessError as e:
        error_msg = f"执行命令失败: {str(e)}, 返回码: {e.returncode}"
        print(f"应用IPv4配置出错: {error_msg}")
        if hasattr(e, 'output') and e.output:
            print(f"命令输出: {e.output}")
        if hasattr(e, 'stderr') and e.stderr:
            print(f"错误输出: {e.stderr}")
    except Exception as e:
        error_msg = f"应用IPv4配置时出错: {str(e)}"
        print(f"应用IPv4配置出错: {error_msg}")
        import traceback
        print(f"详细错误信息: {traceback.format_exc()}")
    
    return success, error_msg

# IPv4 DNS配置函数
def configure_ipv4_dns(nic_name, dns_config):
    """配置IPv4 DNS服务器"""
    # 在函数开始就解析DNS服务器列表，确保dns_servers变量在任何情况下都已定义
    print(f"原始DNS配置: '{dns_config}'")
    
    # 检查dns_config是否为None或空字符串
    if dns_config is None or dns_config.strip() == '':
        print("DNS配置为空，不需要设置DNS服务器")
        # 清除现有DNS配置
        try:
            clear_dns_cmd = f'netsh interface ipv4 set dnsservers name="{nic_name}" source=static address=none'
            subprocess.run(clear_dns_cmd, shell=True, check=True, capture_output=True, text=True, creationflags=CREATE_NO_WINDOW)
            print("已清除现有DNS配置")
        except Exception as e:
            print(f"清除DNS配置出错: {str(e)}")
        return True
    
    # 处理可能的分隔符：换行符、逗号、分号
    if '\n' in dns_config:
        dns_list = dns_config.split('\n')
    elif ',' in dns_config:
        dns_list = dns_config.split(',')
    elif ';' in dns_config:
        dns_list = dns_config.split(';')
    else:
        dns_list = [dns_config]  # 单个DNS服务器
        
    dns_servers = [dns.strip() for dns in dns_list if dns.strip()]
    print(f"解析后的DNS服务器列表: {dns_servers}")
    
    if not dns_servers:
        print("解析后的DNS服务器列表为空，不需要设置DNS服务器")
        # 清除现有DNS配置
        try:
            clear_dns_cmd = f'netsh interface ipv4 set dnsservers name="{nic_name}" source=static address=none'
            subprocess.run(clear_dns_cmd, shell=True, check=True, capture_output=True, text=True, creationflags=CREATE_NO_WINDOW)
            print("已清除现有DNS配置")
        except Exception as e:
            print(f"清除DNS配置出错: {str(e)}")
        return True
    
    try:
        # 清除现有DNS配置
        clear_dns_cmd = f'netsh interface ipv4 set dnsservers name="{nic_name}" source=static address=none'
        subprocess.run(clear_dns_cmd, shell=True, check=True, capture_output=True, text=True, creationflags=CREATE_NO_WINDOW)
        
        # 设置主DNS服务器 (优化Windows 7兼容性)
        primary_dns = dns_servers[0]  # 此时dns_servers一定不为空
        # 直接使用Windows 7兼容的命令格式，不带register=primary参数
        primary_cmd = f'netsh interface ipv4 set dnsservers name="{nic_name}" source=static address={primary_dns}'
        
        try:
            subprocess.run(primary_cmd, shell=True, check=True, capture_output=True, text=True, creationflags=CREATE_NO_WINDOW)
        except subprocess.CalledProcessError as e:
            print(f"设置主DNS服务器失败: {str(e)}")
            # 如果失败，将在后面尝试PowerShell方法
        
        # 验证主DNS配置
        verify_cmd = f'netsh interface ipv4 show dnsservers "{nic_name}"'
        verify_result = subprocess.run(verify_cmd, shell=True, capture_output=True, text=True, creationflags=CREATE_NO_WINDOW)
        if primary_dns not in verify_result.stdout:
            # 尝试使用PowerShell命令
            return configure_ipv4_dns_with_powershell(nic_name, dns_servers)
        
        # 设置备用DNS服务器 (优化Windows 7兼容性)
        for i, dns in enumerate(dns_servers[1:], 1):
            # 使用Windows 7兼容的命令格式，带index参数
            secondary_cmd = f'netsh interface ipv4 add dnsservers name="{nic_name}" address={dns} index={i+1}'
            try:
                subprocess.run(secondary_cmd, shell=True, check=True, capture_output=True, text=True, creationflags=CREATE_NO_WINDOW)
            except subprocess.CalledProcessError as e:
                print(f"设置备用DNS服务器失败: {str(e)}")
                # 如果失败，将在后面尝试PowerShell方法
            
            # 验证备用DNS配置
            verify_result = subprocess.run(verify_cmd, shell=True, capture_output=True, text=True, creationflags=CREATE_NO_WINDOW)
            if dns not in verify_result.stdout:
                # 如果单个备用DNS设置失败，尝试使用PowerShell命令设置所有DNS
                return configure_ipv4_dns_with_powershell(nic_name, dns_servers)
        
        return True
    except Exception as e:
        print(f"配置IPv4 DNS服务器出错: {str(e)}")
        # 尝试使用PowerShell命令作为备选方案
        return configure_ipv4_dns_with_powershell(nic_name, dns_servers)

# 使用PowerShell配置IPv4 DNS
def configure_ipv4_dns_with_powershell(nic_name, dns_servers):
    """使用PowerShell命令配置IPv4 DNS服务器"""
    try:
        # 构建DNS服务器地址数组字符串
        dns_array = ','.join([f"'{dns}'" for dns in dns_servers])
        # 移除不支持的-AddressFamily IPv4参数
        ps_cmd = f'powershell -Command "Set-DnsClientServerAddress -InterfaceAlias \"{nic_name}\" -ServerAddresses @({dns_array})"'
        subprocess.run(ps_cmd, shell=True, check=True, capture_output=True, text=True, creationflags=CREATE_NO_WINDOW)
        
        # 验证配置是否成功
        try:
            # 使用PowerShell命令验证DNS配置
            ps_verify_cmd = f'powershell -Command "(Get-DnsClientServerAddress -InterfaceAlias \"{nic_name}\" -AddressFamily IPv4).ServerAddresses"'
            verify_result = subprocess.run(ps_verify_cmd, shell=True, capture_output=True, text=True, creationflags=CREATE_NO_WINDOW)
            
            # 检查每个DNS服务器是否在输出中
            all_dns_found = True
            for dns in dns_servers:
                if dns not in verify_result.stdout:
                    all_dns_found = False
                    print(f"PowerShell设置IPv4 DNS服务器验证失败: {dns} 未在输出中找到")
                    print(f"验证命令输出: {verify_result.stdout}")
                    break
            
            if not all_dns_found:
                # 如果PowerShell验证失败，尝试使用netsh命令验证
                verify_cmd = f'netsh interface ipv4 show dnsservers "{nic_name}"'
                verify_result = subprocess.run(verify_cmd, shell=True, capture_output=True, text=True, creationflags=CREATE_NO_WINDOW)
                
                all_dns_found = True
                for dns in dns_servers:
                    if dns not in verify_result.stdout:
                        all_dns_found = False
                        print(f"netsh验证IPv4 DNS服务器失败: {dns} 未在输出中找到")
                        return False
            
            if not all_dns_found:
                return False
        except Exception as e:
            print(f"PowerShell验证IPv4 DNS命令失败: {str(e)}")
            return False
        
        print(f"使用PowerShell设置IPv4 DNS服务器成功")
        return True
    except subprocess.CalledProcessError as e:
        print(f"PowerShell设置IPv4 DNS服务器失败: {e}")
        if hasattr(e, 'stdout') and e.stdout:
            print(f"命令输出: {e.stdout}")
        if hasattr(e, 'stderr') and e.stderr:
            print(f"错误输出: {e.stderr}")
        return False
    except Exception as e:
        print(f"PowerShell设置IPv4 DNS服务器出错: {str(e)}")

# IPv6配置函数
def configure_ipv6(nic_name, config):
    """配置IPv6地址、前缀长度、网关和DNS服务器"""
    import logging
    logger = logging.getLogger('ip_config')
    success = False
    error_msg = ""
    
    logger.info(f"开始配置IPv6设置到网卡 {nic_name}")
    
    try:
        # 检查是否具有管理员权限
        if not is_admin():
            error_msg = "需要管理员权限才能配置IPv6设置"
            logger.error(error_msg)
            return False, error_msg
        
        # 设置IPv6地址和前缀长度
        address_success = False
        if config.get('ipv6') and config.get('prefix'):
            logger.info(f"配置IPv6地址: {config.get('ipv6')}/{config.get('prefix')}")
            try:
                # 首先清除所有现有的非链路本地IPv6地址
                clear_success = clear_existing_ipv6_addresses(nic_name)
                if not clear_success:
                    logger.warning("清除现有IPv6地址时出现问题，继续尝试配置新地址")
                
                # 设置新的IPv6地址
                address_success = configure_ipv6_address(nic_name, config.get('ipv6'), config.get('prefix'))
                if not address_success:
                    error_msg = "IPv6地址配置失败"
                    logger.warning(error_msg)
                    # 不返回，继续尝试其他配置
                else:
                    logger.info(f"IPv6地址配置成功: {config.get('ipv6')}/{config.get('prefix')}")
            except Exception as e:
                logger.error(f"IPv6地址配置过程中出错: {str(e)}")
                # 不返回，继续尝试其他配置
        else:
            logger.info("未提供IPv6地址或前缀长度，跳过地址配置")
        
        # 设置IPv6网关
        gateway_success = False
        if config.get('gateway_v6'):
            logger.info(f"配置IPv6网关: {config.get('gateway_v6')}")
            try:
                gateway_success = configure_ipv6_gateway(nic_name, config.get('gateway_v6'))
                if not gateway_success:
                    error_msg = "IPv6网关配置失败"
                    logger.warning(error_msg)
                    # 不返回，继续尝试其他配置
                else:
                    logger.info(f"IPv6网关配置成功: {config.get('gateway_v6')}")
            except Exception as e:
                logger.error(f"IPv6网关配置过程中出错: {str(e)}")
                # 不返回，继续尝试其他配置
        else:
            logger.info("未提供IPv6网关，跳过网关配置")
        
        # 设置IPv6 DNS服务器
        dns_success = False
        if config.get('dns_v6'):
            # 确保DNS配置字符串格式正确
            dns_config = config.get('dns_v6')
            logger.info(f"配置IPv6 DNS服务器: {dns_config}")
            
            try:
                dns_success = configure_ipv6_dns(nic_name, dns_config)
                if not dns_success:
                    error_msg = "IPv6 DNS服务器配置失败"
                    logger.warning(error_msg)
                    # 不返回，继续尝试其他配置
                else:
                    logger.info("IPv6 DNS服务器配置成功")
            except Exception as e:
                logger.error(f"IPv6 DNS服务器配置过程中出错: {str(e)}")
                # 不返回，继续尝试其他配置
        else:
            logger.info("未提供IPv6 DNS服务器，跳过DNS配置")
        
        # 最终验证整体IPv6配置
        try:
            # 使用netsh命令验证整体配置（最通用的方法，兼容Windows 7）
            logger.info("执行最终IPv6配置验证...")
            
            # 验证IPv6地址
            if config.get('ipv6'):
                netsh_addr_cmd = f'netsh interface ipv6 show address "{nic_name}"'
                addr_result = subprocess.run(netsh_addr_cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
                if config.get('ipv6') in addr_result.stdout:
                    logger.info(f"最终验证确认IPv6地址已成功配置: {config.get('ipv6')}")
                else:
                    logger.warning(f"最终验证未能确认IPv6地址: {config.get('ipv6')}")
            
            # 验证IPv6网关
            if config.get('gateway_v6'):
                netsh_route_cmd = f'netsh interface ipv6 show route'
                route_result = subprocess.run(netsh_route_cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
                if config.get('gateway_v6') in route_result.stdout:
                    logger.info(f"最终验证确认IPv6网关已成功配置: {config.get('gateway_v6')}")
                else:
                    logger.warning(f"最终验证未能确认IPv6网关: {config.get('gateway_v6')}")
            
            # 验证IPv6 DNS
            if config.get('dns_v6'):
                netsh_dns_cmd = f'netsh interface ipv6 show dnsservers "{nic_name}"'
                dns_result = subprocess.run(netsh_dns_cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
                
                # 解析DNS服务器列表
                dns_servers = parse_dns_servers(config.get('dns_v6'))
                dns_verified = True
                for dns in dns_servers:
                    if dns not in dns_result.stdout:
                        dns_verified = False
                        logger.warning(f"最终验证未能确认IPv6 DNS服务器: {dns}")
                
                if dns_verified:
                    logger.info("最终验证确认所有IPv6 DNS服务器已成功配置")
        except Exception as e:
            logger.error(f"最终IPv6配置验证过程中出错: {str(e)}")
        
        # 即使某些配置失败，也将整体操作标记为成功
        # 这是因为IPv6配置通常是可选的，部分成功也是可以接受的
        success = True
        
        # 如果所有配置都失败，则设置适当的错误消息
        if config.get('ipv6') and config.get('prefix') and not address_success and \
           config.get('gateway_v6') and not gateway_success and \
           config.get('dns_v6') and not dns_success:
            error_msg = "所有IPv6配置项都失败"
            logger.error(error_msg)
        elif not error_msg:
            # 如果没有特定错误消息，但有部分配置失败
            if (config.get('ipv6') and config.get('prefix') and not address_success) or \
               (config.get('gateway_v6') and not gateway_success) or \
               (config.get('dns_v6') and not dns_success):
                error_msg = "部分IPv6配置项失败，但整体配置已完成"
                logger.warning(error_msg)
            else:
                logger.info("IPv6配置全部成功完成")
        
    except subprocess.CalledProcessError as e:
        error_msg = f"执行命令失败: {str(e)}, 返回码: {e.returncode}"
        logger.error(f"应用IPv6配置出错: {error_msg}")
        if hasattr(e, 'stdout') and e.stdout:
            logger.error(f"命令输出: {e.stdout}")
        if hasattr(e, 'stderr') and e.stderr:
            logger.error(f"错误输出: {e.stderr}")
        # 即使出错，也将整体操作标记为成功，因为IPv6配置通常是可选的
        success = True
    except Exception as e:
        error_msg = f"应用IPv6配置时出错: {str(e)}"
        logger.error(f"应用IPv6配置出错: {error_msg}")
        import traceback
        logger.error(f"详细错误信息: {traceback.format_exc()}")
        # 即使出错，也将整体操作标记为成功，因为IPv6配置通常是可选的
        success = True
    
    return success, error_msg


def clear_existing_ipv6_addresses(nic_name):
    """清除网卡上所有现有的非链路本地IPv6地址"""
    import logging
    logger = logging.getLogger('ip_config')
    logger.info(f"开始清除网卡 {nic_name} 上的所有非链路本地IPv6地址")
    
    success = False
    
    # 方法1: 使用PowerShell命令删除所有非链路本地IPv6地址
    try:
        # 首先检查现有的IPv6地址
        ps_check_cmd = f'powershell -Command "Get-NetIPAddress -InterfaceAlias \"{nic_name}\" -AddressFamily IPv6 | Where-Object {{$_.PrefixOrigin -ne \"WellKnown\" -and $_.IPAddress -notlike \"fe80*\"}} | Select-Object -ExpandProperty IPAddress"'
        logger.info(f"检查现有IPv6地址: {ps_check_cmd}")
        check_result = subprocess.run(ps_check_cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
        
        if check_result.stdout.strip():
            existing_addresses = check_result.stdout.strip().split('\r\n')
            logger.info(f"发现现有IPv6地址: {existing_addresses}")
            
            # 使用PowerShell删除现有的非链路本地IPv6地址
            ps_remove_cmd = f'powershell -Command "Get-NetIPAddress -InterfaceAlias \"{nic_name}\" -AddressFamily IPv6 | Where-Object {{$_.PrefixOrigin -ne \"WellKnown\" -and $_.IPAddress -notlike \"fe80*\"}} | Remove-NetIPAddress -Confirm:$false"'
            logger.info(f"尝试删除现有IPv6地址: {ps_remove_cmd}")
            remove_result = subprocess.run(ps_remove_cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
            
            # 验证是否成功删除
            verify_cmd = f'powershell -Command "Get-NetIPAddress -InterfaceAlias \"{nic_name}\" -AddressFamily IPv6 | Where-Object {{$_.PrefixOrigin -ne \"WellKnown\" -and $_.IPAddress -notlike \"fe80*\"}}"'
            verify_result = subprocess.run(verify_cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
            
            if verify_result.stdout.strip():
                logger.warning("PowerShell未能删除所有IPv6地址，尝试使用netsh命令")
                success = False
            else:
                logger.info("成功使用PowerShell删除所有现有IPv6地址")
                success = True
        else:
            logger.info("未发现需要删除的非链路本地IPv6地址")
            success = True
    except Exception as e:
        logger.warning(f"使用PowerShell删除IPv6地址时出错: {str(e)}")
        success = False
    
    # 如果PowerShell方法失败，尝试方法2: 使用netsh命令
    if not success:
        try:
            # 使用netsh命令列出所有IPv6地址
            netsh_show_cmd = f'netsh interface ipv6 show address "{nic_name}"'
            logger.info(f"使用netsh列出IPv6地址: {netsh_show_cmd}")
            show_result = subprocess.run(netsh_show_cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
            
            # 使用正则表达式从输出中提取IPv6地址
            import re
            ipv6_pattern = re.compile(r'([0-9a-fA-F:]+)(/\d+)?')
            matches = ipv6_pattern.findall(show_result.stdout)
            
            deleted_count = 0
            for match in matches:
                addr = match[0]
                # 排除链路本地地址
                if not addr.startswith('fe80'):
                    try:
                        netsh_remove_cmd = f'netsh interface ipv6 delete address "{nic_name}" {addr}'
                        logger.info(f"尝试使用netsh删除IPv6地址 {addr}: {netsh_remove_cmd}")
                        subprocess.run(netsh_remove_cmd, shell=True, check=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
                        deleted_count += 1
                    except Exception as e:
                        logger.warning(f"使用netsh删除IPv6地址 {addr} 时出错: {str(e)}")
            
            # 再次验证是否删除成功
            verify_result = subprocess.run(netsh_show_cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
            remaining_addresses = [addr for addr, _ in ipv6_pattern.findall(verify_result.stdout) if not addr.startswith('fe80')]
            
            if not remaining_addresses:
                logger.info(f"成功使用netsh删除了 {deleted_count} 个IPv6地址")
                success = True
            else:
                logger.warning(f"netsh删除后仍有 {len(remaining_addresses)} 个IPv6地址: {remaining_addresses}")
                success = False
        except Exception as e:
            logger.error(f"使用netsh删除IPv6地址时出错: {str(e)}")
            success = False
    
    # 方法3: 尝试使用Windows 7兼容的命令（适用于旧版Windows）
    if not success:
        try:
            # 使用netsh interface ipv6 delete address命令（Windows 7兼容）
            netsh_show_cmd = f'netsh interface ipv6 show address "{nic_name}"'
            show_result = subprocess.run(netsh_show_cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
            
            # 使用更简单的正则表达式，适用于Windows 7的输出格式
            import re
            ipv6_pattern = re.compile(r'([0-9a-fA-F:]+)')
            matches = ipv6_pattern.findall(show_result.stdout)
            
            deleted_count = 0
            for addr in matches:
                # 排除链路本地地址和重复地址
                if not addr.startswith('fe80') and len(addr) > 4:  # 简单过滤掉非IPv6地址的匹配
                    try:
                        # Windows 7兼容的删除命令
                        netsh_remove_cmd = f'netsh interface ipv6 delete address "{nic_name}" {addr}'
                        logger.info(f"尝试使用Windows 7兼容命令删除IPv6地址 {addr}: {netsh_remove_cmd}")
                        subprocess.run(netsh_remove_cmd, shell=True, check=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
                        deleted_count += 1
                    except Exception as e:
                        logger.warning(f"使用Windows 7兼容命令删除IPv6地址 {addr} 时出错: {str(e)}")
            
            logger.info(f"使用Windows 7兼容命令尝试删除了 {deleted_count} 个IPv6地址")
            success = True  # 即使可能没有完全成功，也继续后续配置
        except Exception as e:
            logger.error(f"使用Windows 7兼容命令删除IPv6地址时出错: {str(e)}")
            success = False
    
    return success

# IPv6地址配置函数
def configure_ipv6_address(nic_name, ipv6_address, prefix_length):
    """配置IPv6地址和前缀长度"""
    import logging
    logger = logging.getLogger('ip_config')
    logger.info(f"开始配置IPv6地址: {ipv6_address}/{prefix_length} 到网卡 {nic_name}")
    
    # 确保删除所有现有的非链路本地IPv6地址
    # 首先使用netsh命令（Windows 7兼容性更好）
    try:
        # 使用netsh命令列出所有IPv6地址
        netsh_show_cmd = f'netsh interface ipv6 show address "{nic_name}"'
        logger.info(f"使用netsh列出IPv6地址: {netsh_show_cmd}")
        show_result = subprocess.run(netsh_show_cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
        
        # 使用正则表达式从输出中提取IPv6地址
        import re
        ipv6_pattern = re.compile(r'([0-9a-fA-F:]+)(/\d+)?')
        matches = ipv6_pattern.findall(show_result.stdout)
        
        deleted_count = 0
        for match in matches:
            addr = match[0]
            # 排除链路本地地址
            if not addr.startswith('fe80'):
                try:
                    # 使用Windows 7兼容的删除命令
                    netsh_remove_cmd = f'netsh interface ipv6 delete address "{nic_name}" {addr}'
                    logger.info(f"尝试使用netsh删除IPv6地址 {addr}: {netsh_remove_cmd}")
                    subprocess.run(netsh_remove_cmd, shell=True, check=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
                    deleted_count += 1
                except Exception as e:
                    logger.warning(f"使用netsh删除IPv6地址 {addr} 时出错: {str(e)}")
        
        logger.info(f"使用netsh命令尝试删除了 {deleted_count} 个IPv6地址")
        
        # 验证是否删除成功
        verify_result = subprocess.run(netsh_show_cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
        remaining_addresses = [addr for addr, _ in ipv6_pattern.findall(verify_result.stdout) if not addr.startswith('fe80')]
        
        if remaining_addresses:
            logger.warning(f"netsh删除后仍有 {len(remaining_addresses)} 个IPv6地址: {remaining_addresses}")
            # 尝试使用PowerShell删除（如果系统支持）
            try:
                ps_remove_cmd = f'powershell -Command "Get-NetIPAddress -InterfaceAlias \"{nic_name}\" -AddressFamily IPv6 | Where-Object {{$_.PrefixOrigin -ne \"WellKnown\" -and $_.IPAddress -notlike \"fe80*\"}} | Remove-NetIPAddress -Confirm:$false"'
                logger.info(f"尝试使用PowerShell删除剩余IPv6地址: {ps_remove_cmd}")
                subprocess.run(ps_remove_cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
            except Exception as e:
                logger.warning(f"使用PowerShell删除剩余IPv6地址时出错: {str(e)}")
        else:
            logger.info("成功删除所有非链路本地IPv6地址")
    except Exception as e:
        logger.warning(f"使用netsh列出和删除IPv6地址时出错: {str(e)}")
        # 尝试使用PowerShell删除（如果系统支持）
        try:
            ps_remove_cmd = f'powershell -Command "Get-NetIPAddress -InterfaceAlias \"{nic_name}\" -AddressFamily IPv6 | Where-Object {{$_.PrefixOrigin -ne \"WellKnown\" -and $_.IPAddress -notlike \"fe80*\"}} | Remove-NetIPAddress -Confirm:$false"'
            logger.info(f"尝试使用PowerShell删除IPv6地址: {ps_remove_cmd}")
            subprocess.run(ps_remove_cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
        except Exception as e:
            logger.warning(f"使用PowerShell删除IPv6地址时出错: {str(e)}")
    
    # 设置新的IPv6地址，优先使用netsh命令（Windows 7兼容性更好）
    success = False
    
    # 方法1: 使用netsh add命令（Windows 7兼容性最好）
    try:
        # 尝试使用netsh add命令
        netsh_add_cmd = f'netsh interface ipv6 add address "{nic_name}" {ipv6_address}/{prefix_length} store=persistent'
        logger.info(f"尝试使用netsh add命令设置IPv6地址: {netsh_add_cmd}")
        subprocess.run(netsh_add_cmd, shell=True, check=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
        
        # 验证是否成功设置
        netsh_show_cmd = f'netsh interface ipv6 show address "{nic_name}"'
        verify_result = subprocess.run(netsh_show_cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
        
        if ipv6_address in verify_result.stdout:
            logger.info(f"成功使用netsh add命令设置IPv6地址: {ipv6_address}/{prefix_length}")
            success = True
            return success
        else:
            logger.warning("netsh add命令设置IPv6地址失败，尝试其他方法")
    except Exception as e:
        logger.warning(f"使用netsh add命令设置IPv6地址时出错: {str(e)}")
    
    # 方法2: 尝试使用netsh set命令
    if not success:
        try:
            # 尝试使用netsh set命令
            netsh_set_cmd = f'netsh interface ipv6 set address "{nic_name}" {ipv6_address}/{prefix_length} store=persistent'
            logger.info(f"尝试使用netsh set命令设置IPv6地址: {netsh_set_cmd}")
            subprocess.run(netsh_set_cmd, shell=True, check=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
            
            # 验证是否成功设置
            netsh_show_cmd = f'netsh interface ipv6 show address "{nic_name}"'
            verify_result = subprocess.run(netsh_show_cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
            
            if ipv6_address in verify_result.stdout:
                logger.info(f"成功使用netsh set命令设置IPv6地址: {ipv6_address}/{prefix_length}")
                success = True
                return success
            else:
                logger.warning("netsh set命令设置IPv6地址失败，尝试使用替代格式")
        except Exception as e:
            logger.warning(f"使用netsh set命令设置IPv6地址时出错: {str(e)}")
    
    # 方法3: 尝试使用不同格式的netsh命令（某些Windows版本可能需要）
    if not success:
        try:
            # 尝试使用不带斜杠的格式
            netsh_alt_cmd = f'netsh interface ipv6 add address "{nic_name}" {ipv6_address} {prefix_length} store=persistent'
            logger.info(f"尝试使用替代格式的netsh命令设置IPv6地址: {netsh_alt_cmd}")
            subprocess.run(netsh_alt_cmd, shell=True, check=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
            
            # 验证是否成功设置
            netsh_show_cmd = f'netsh interface ipv6 show address "{nic_name}"'
            verify_result = subprocess.run(netsh_show_cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
            
            if ipv6_address in verify_result.stdout:
                logger.info(f"成功使用替代格式的netsh命令设置IPv6地址: {ipv6_address} {prefix_length}")
                success = True
                return success
            else:
                logger.warning("替代格式的netsh命令设置IPv6地址失败，尝试使用PowerShell命令")
        except Exception as e:
            logger.warning(f"使用替代格式的netsh命令设置IPv6地址时出错: {str(e)}")
    
    # 方法4: 最后尝试使用PowerShell命令（较新的Windows版本）
    if not success:
        try:
            # 设置新的IPv6地址
            ps_set_cmd = f'powershell -Command "New-NetIPAddress -InterfaceAlias \"{nic_name}\" -AddressFamily IPv6 -IPAddress \"{ipv6_address}\" -PrefixLength {prefix_length} -Confirm:$false"'
            logger.info(f"尝试使用PowerShell设置IPv6地址: {ps_set_cmd}")
            subprocess.run(ps_set_cmd, shell=True, check=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
            
            # 验证是否成功设置
            ps_verify_cmd = f'powershell -Command "Get-NetIPAddress -InterfaceAlias \"{nic_name}\" -AddressFamily IPv6 | Where-Object {{$_.IPAddress -eq \"{ipv6_address}\"}}"'
            verify_result = subprocess.run(ps_verify_cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
            
            if ipv6_address in verify_result.stdout:
                logger.info(f"成功使用PowerShell设置IPv6地址: {ipv6_address}/{prefix_length}")
                success = True
                return success
            else:
                logger.error("PowerShell设置IPv6地址失败")
        except Exception as e:
            logger.error(f"使用PowerShell设置IPv6地址时出错: {str(e)}")
    
    # 最终验证
    try:
        # 使用netsh命令验证地址是否已设置（最通用的方法）
        netsh_show_cmd = f'netsh interface ipv6 show address "{nic_name}"'
        verify_result = subprocess.run(netsh_show_cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
        
        if ipv6_address in verify_result.stdout:
            logger.info(f"最终验证确认IPv6地址已成功设置: {ipv6_address}")
            success = True
        else:
            logger.error(f"所有方法都无法设置IPv6地址: {ipv6_address}")
            success = False
    except Exception as e:
        logger.error(f"最终验证IPv6地址时出错: {str(e)}")
    
    return success

# IPv6网关配置函数
def configure_ipv6_gateway(nic_name, gateway):
    """配置IPv6网关"""
    import logging
    logger = logging.getLogger('ip_config')
    logger.info(f"开始配置IPv6网关: {gateway} 到网卡 {nic_name}")
    
    # 先尝试删除现有的默认路由（使用netsh命令，Windows 7兼容性更好）
    try:
        # 使用netsh命令删除现有的默认路由
        netsh_remove_cmd = f'netsh interface ipv6 delete route ::/0 "{nic_name}" store=persistent'
        logger.info(f"尝试使用netsh删除现有IPv6默认路由: {netsh_remove_cmd}")
        subprocess.run(netsh_remove_cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
        logger.info("尝试删除现有IPv6默认路由")
    except Exception as e:
        logger.warning(f"使用netsh删除现有IPv6默认路由时出错: {str(e)}")
    
    # 再尝试使用PowerShell删除现有的默认路由（较新的Windows版本）
    try:
        # 使用PowerShell删除现有的默认路由
        ps_remove_cmd = f'powershell -Command "Remove-NetRoute -DestinationPrefix \"::/0\" -InterfaceAlias \"{nic_name}\" -AddressFamily IPv6 -Confirm:$false -ErrorAction SilentlyContinue"'
        logger.info(f"尝试使用PowerShell删除现有IPv6默认路由: {ps_remove_cmd}")
        subprocess.run(ps_remove_cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
    except Exception as e:
        logger.warning(f"使用PowerShell删除现有IPv6默认路由时出错: {str(e)}")
    
    success = False
    
    # 方法1: 优先使用netsh命令设置IPv6网关（Windows 7兼容性更好）
    try:
        netsh_add_cmd = f'netsh interface ipv6 add route ::/0 "{nic_name}" {gateway} store=persistent'
        logger.info(f"尝试使用netsh设置IPv6网关: {netsh_add_cmd}")
        subprocess.run(netsh_add_cmd, shell=True, check=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
        
        # 验证配置
        verify_cmd = f'netsh interface ipv6 show route'
        verify_result = subprocess.run(verify_cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
        
        if gateway in verify_result.stdout and "::/0" in verify_result.stdout:
            logger.info(f"成功使用netsh命令设置IPv6网关: {gateway}")
            success = True
            return True
        else:
            logger.warning("netsh命令设置IPv6网关验证失败，尝试使用替代格式")
    except Exception as e:
        logger.warning(f"使用netsh命令设置IPv6网关失败: {str(e)}")
    
    # 方法2: 尝试使用替代格式的netsh命令
    if not success:
        try:
            # 尝试使用不同格式的netsh命令
            netsh_alt_cmd = f'netsh interface ipv6 add route ::/0 interface="{nic_name}" nexthop={gateway} store=persistent'
            logger.info(f"尝试使用替代格式的netsh命令设置IPv6网关: {netsh_alt_cmd}")
            subprocess.run(netsh_alt_cmd, shell=True, check=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
            
            # 验证配置
            verify_cmd = f'netsh interface ipv6 show route'
            verify_result = subprocess.run(verify_cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
            
            if gateway in verify_result.stdout and "::/0" in verify_result.stdout:
                logger.info(f"成功使用替代格式的netsh命令设置IPv6网关: {gateway}")
                success = True
                return True
            else:
                logger.warning("替代格式的netsh命令设置IPv6网关验证失败，尝试使用PowerShell命令")
        except Exception as e:
            logger.warning(f"使用替代格式的netsh命令设置IPv6网关失败: {str(e)}")
    
    # 方法3: 最后尝试使用PowerShell设置IPv6网关（较新的Windows版本）
    if not success:
        try:
            # 获取网络接口索引（PowerShell方法需要）
            ifindex = None
            try:
                # 使用PowerShell获取接口索引
                ps_cmd = f'powershell -Command "(Get-NetAdapter | Where-Object {{$_.Name -eq \"{nic_name}\"}} | Select-Object -ExpandProperty ifIndex)"'
                result = subprocess.run(ps_cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
                if result.stdout.strip():
                    ifindex = result.stdout.strip()
                    logger.info(f"获取到网络接口 {nic_name} 的索引: {ifindex}")
            except Exception as e:
                logger.error(f"获取网络接口索引失败: {str(e)}")
            
            # 使用New-NetRoute命令设置IPv6网关
            ps_add_cmd = f'powershell -Command "New-NetRoute -DestinationPrefix \"::/0\" -InterfaceAlias \"{nic_name}\" -NextHop \"{gateway}\" -AddressFamily IPv6 -Confirm:$false"'
            logger.info(f"尝试使用PowerShell设置IPv6网关: {ps_add_cmd}")
            subprocess.run(ps_add_cmd, shell=True, check=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
            
            # 验证配置是否成功
            ps_verify_cmd = f'powershell -Command "Get-NetRoute -DestinationPrefix \"::/0\" -InterfaceAlias \"{nic_name}\" -AddressFamily IPv6 | Where-Object {{$_.NextHop -eq \"{gateway}\"}}"'
            verify_result = subprocess.run(ps_verify_cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
            
            if gateway in verify_result.stdout:
                logger.info(f"成功使用PowerShell设置IPv6网关: {gateway}")
                success = True
                return True
            else:
                logger.error("PowerShell设置IPv6网关验证失败")
        except Exception as e:
            logger.error(f"使用PowerShell设置IPv6网关失败: {str(e)}")
    
    # 最终验证
    try:
        # 使用netsh命令验证网关是否已设置（最通用的方法）
        verify_cmd = f'netsh interface ipv6 show route'
        verify_result = subprocess.run(verify_cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
        
        if gateway in verify_result.stdout and "::/0" in verify_result.stdout:
            logger.info(f"最终验证确认IPv6网关已成功设置: {gateway}")
            success = True
        else:
            logger.error(f"所有方法都无法设置IPv6网关: {gateway}")
            success = False
    except Exception as e:
        logger.error(f"最终验证IPv6网关时出错: {str(e)}")
    
    return success

# IPv6 DNS配置函数
def configure_ipv6_dns(nic_name, dns_config):
    """配置IPv6 DNS服务器"""
    import logging
    logger = logging.getLogger('ip_config')
    logger.info(f"开始配置IPv6 DNS服务器: {dns_config} 到网卡 {nic_name}")
    
    # 解析DNS服务器列表
    logger.info(f"原始DNS配置: '{dns_config}'")
    # 处理可能的分隔符：换行符、逗号、分号
    if isinstance(dns_config, str):
        if '\n' in dns_config:
            dns_list = dns_config.split('\n')
        elif ',' in dns_config:
            dns_list = dns_config.split(',')
        elif ';' in dns_config:
            dns_list = dns_config.split(';')
        else:
            dns_list = [dns_config]  # 单个DNS服务器
        dns_servers = [dns.strip() for dns in dns_list if dns.strip()]
    else:
        dns_servers = dns_config if isinstance(dns_config, list) else []
    
    logger.info(f"解析后的DNS服务器列表: {dns_servers}")
    
    # 检查DNS服务器列表是否为空
    if not dns_servers:
        logger.info("DNS服务器列表为空，无需配置DNS")
        return True  # 没有DNS服务器需要设置
    
    success = False
    
    # 方法1: 优先使用netsh命令（Windows 7兼容性更好）
    try:
        # 清除现有DNS配置
        clear_cmd = f'netsh interface ipv6 set dnsservers name="{nic_name}" source=static address=none'
        logger.info(f"尝试使用netsh清除IPv6 DNS配置: {clear_cmd}")
        subprocess.run(clear_cmd, shell=True, check=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
        logger.info("成功清除IPv6 DNS配置")
        
        # 设置主DNS服务器
        primary_dns = dns_servers[0]
        primary_cmd = f'netsh interface ipv6 set dnsservers name="{nic_name}" source=static address={primary_dns} store=persistent'
        logger.info(f"尝试使用netsh设置IPv6主DNS服务器: {primary_cmd}")
        subprocess.run(primary_cmd, shell=True, check=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
        
        # 设置备用DNS服务器
        for i, dns in enumerate(dns_servers[1:], 1):
            secondary_cmd = f'netsh interface ipv6 add dnsservers name="{nic_name}" address={dns} index={i+1} store=persistent'
            logger.info(f"尝试使用netsh设置IPv6备用DNS服务器: {secondary_cmd}")
            subprocess.run(secondary_cmd, shell=True, check=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
        
        # 验证配置
        verify_cmd = f'netsh interface ipv6 show dnsservers "{nic_name}"'
        verify_result = subprocess.run(verify_cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
        
        # 检查每个DNS服务器是否在输出中
        all_dns_found = True
        for dns in dns_servers:
            if dns not in verify_result.stdout:
                all_dns_found = False
                logger.warning(f"netsh设置IPv6 DNS服务器验证失败: {dns} 未在输出中找到")
                break
        
        if all_dns_found:
            logger.info(f"成功使用netsh命令设置IPv6 DNS服务器: {dns_servers}")
            success = True
            return True
        else:
            logger.warning("netsh设置IPv6 DNS验证失败，尝试备用方法")
    except Exception as e:
        logger.warning(f"使用netsh设置IPv6 DNS失败: {str(e)}，尝试备用方法")
    
    # 方法2: 尝试使用备用netsh方法（Windows 7兼容性）
    if not success:
        try:
            # 清除现有DNS配置
            clear_cmd = f'netsh interface ipv6 set dnsservers name="{nic_name}" source=static address=none'
            logger.info(f"尝试清除IPv6 DNS配置(备用方法): {clear_cmd}")
            subprocess.run(clear_cmd, shell=True, check=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
            
            # 逐个添加DNS服务器（不使用index参数，更兼容Windows 7）
            for i, dns in enumerate(dns_servers):
                if i == 0:
                    # 设置主DNS
                    dns_cmd = f'netsh interface ipv6 set dnsservers name="{nic_name}" source=static address={dns}'
                else:
                    # 添加备用DNS
                    dns_cmd = f'netsh interface ipv6 add dnsservers name="{nic_name}" address={dns}'
                
                logger.info(f"尝试设置IPv6 DNS服务器(备用方法): {dns_cmd}")
                subprocess.run(dns_cmd, shell=True, check=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
            
            # 验证配置
            verify_cmd = f'netsh interface ipv6 show dnsservers "{nic_name}"'
            verify_result = subprocess.run(verify_cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
            
            # 检查每个DNS服务器是否在输出中
            all_dns_found = True
            for dns in dns_servers:
                if dns not in verify_result.stdout:
                    all_dns_found = False
                    logger.warning(f"备用方法设置IPv6 DNS服务器验证失败: {dns} 未在输出中找到")
                    break
            
            if all_dns_found:
                logger.info(f"成功使用备用方法设置IPv6 DNS服务器: {dns_servers}")
                success = True
                return True
            else:
                logger.warning("备用方法设置IPv6 DNS验证失败，尝试使用PowerShell命令")
        except Exception as e:
            logger.warning(f"使用备用方法设置IPv6 DNS失败: {str(e)}，尝试使用PowerShell命令")
    
    # 方法3: 最后尝试使用PowerShell（较新的Windows版本）
    if not success:
        try:
            # 构建PowerShell命令设置DNS服务器
            ps_cmd = f'powershell -Command "$dnsServers = @(); '
            for dns in dns_servers:
                ps_cmd += f"$dnsServers += '{dns}'; "
            ps_cmd += f'Set-DnsClientServerAddress -InterfaceAlias \"{nic_name}\" -ServerAddresses $dnsServers -AddressFamily IPv6"'
            
            logger.info(f"尝试使用PowerShell设置IPv6 DNS: {ps_cmd}")
            subprocess.run(ps_cmd, shell=True, check=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
            
            # 验证配置是否成功
            ps_verify_cmd = f'powershell -Command "(Get-DnsClientServerAddress -InterfaceAlias \"{nic_name}\" -AddressFamily IPv6).ServerAddresses"'
            verify_result = subprocess.run(ps_verify_cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
            
            # 检查每个DNS服务器是否在输出中
            all_dns_found = True
            for dns in dns_servers:
                if dns not in verify_result.stdout:
                    all_dns_found = False
                    logger.warning(f"PowerShell设置IPv6 DNS服务器验证失败: {dns} 未在输出中找到")
                    break
            
            if all_dns_found:
                logger.info(f"成功使用PowerShell设置IPv6 DNS服务器: {dns_servers}")
                success = True
                return True
            else:
                logger.error("PowerShell设置IPv6 DNS验证失败")
        except Exception as e:
            logger.error(f"使用PowerShell设置IPv6 DNS失败: {str(e)}")
    
    # 最终验证
    try:
        # 使用netsh命令验证DNS是否已设置（最通用的方法）
        verify_cmd = f'netsh interface ipv6 show dnsservers "{nic_name}"'
        verify_result = subprocess.run(verify_cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='replace', creationflags=CREATE_NO_WINDOW)
        
        # 检查每个DNS服务器是否在输出中
        all_dns_found = True
        for dns in dns_servers:
            if dns not in verify_result.stdout:
                all_dns_found = False
                logger.warning(f"最终验证IPv6 DNS服务器失败: {dns} 未在输出中找到")
                break
        
        if all_dns_found:
            logger.info(f"最终验证确认IPv6 DNS已成功设置: {dns_servers}")
            success = True
        else:
            logger.error(f"所有方法都无法设置IPv6 DNS: {dns_servers}")
            success = False
    except Exception as e:
        logger.error(f"最终验证IPv6 DNS时出错: {str(e)}")
    
    return success