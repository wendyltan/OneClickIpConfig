import subprocess
from subprocess import CREATE_NO_WINDOW
from log_config import logger

# 导入IP配置模块
from ip_config import configure_ipv4, configure_ipv6

def apply_config(is_ipv4, nic_name, config):
    """应用IP配置更改
    
    Args:
        is_ipv4: 是否为IPv4配置
        nic_name: 网卡名称
        config: 配置参数字典
        
    Returns:
        tuple: (success, error_msg)
    """
    success = False
    error_msg = ""
    
    try:
        if config['auto']:
            # 设置自动获取IP地址
            if is_ipv4:
                # 设置IPv4为自动获取
                cmd = f'netsh interface ipv4 set address name="{nic_name}" source=dhcp'
                subprocess.run(cmd, shell=True, check=True, creationflags=CREATE_NO_WINDOW)
                # 设置DNS为自动获取
                cmd = f'netsh interface ipv4 set dnsservers name="{nic_name}" source=dhcp'
                subprocess.run(cmd, shell=True, check=True, creationflags=CREATE_NO_WINDOW)
                # 验证配置是否成功
                verify_cmd = f'netsh interface ipv4 show config name="{nic_name}"'
                verify_result = subprocess.run(verify_cmd, shell=True, capture_output=True, text=True, creationflags=CREATE_NO_WINDOW)
                if 'DHCP已启用' not in verify_result.stdout and 'DHCP enabled' not in verify_result.stdout:
                    raise subprocess.CalledProcessError(returncode=1, cmd=cmd, output="DHCP配置验证失败")
                logger.info("IPv4 DHCP配置成功")
            else:
                # 设置IPv6为自动获取
                cmd = f'netsh interface ipv6 set address name="{nic_name}" source=dhcp'
                subprocess.run(cmd, shell=True, check=True, creationflags=CREATE_NO_WINDOW)
                # 设置DNS为自动获取
                cmd = f'netsh interface ipv6 set dnsservers name="{nic_name}" source=dhcp'
                subprocess.run(cmd, shell=True, check=True, creationflags=CREATE_NO_WINDOW)
                # 验证配置是否成功
                verify_cmd = f'netsh interface ipv6 show address interface="{nic_name}"'
                verify_result = subprocess.run(verify_cmd, shell=True, capture_output=True, text=True, creationflags=CREATE_NO_WINDOW)
                if 'DHCP' not in verify_result.stdout:
                    raise subprocess.CalledProcessError(returncode=1, cmd=cmd, output="DHCP配置验证失败")
                logger.info("IPv6 DHCP配置成功")
            success = True
        else:
            # 设置手动IP地址
            if is_ipv4:
                # 准备IPv4配置参数
                ipv4_config = {
                    'ipv4': config['ip'],
                    'mask': config['mask'],
                    'gateway': config['gateway'],
                    'dns': config['dns']
                }
                
                # 调用IPv4配置函数
                success, error_msg = configure_ipv4(nic_name, ipv4_config)
                if success:
                    logger.info(f"IPv4配置成功: {config['ip']}")
                else:
                    logger.error(f"IPv4配置失败: {error_msg}")
            else:
                # 准备IPv6配置参数
                ipv6_config = {
                    'ipv6': config['ipv6'],
                    'prefix': config['prefix'],
                    'gateway_v6': config['gateway_v6'],
                    'dns_v6': config['dns_v6']
                }
                
                # 调用IPv6配置函数
                success, error_msg = configure_ipv6(nic_name, ipv6_config)
                if success:
                    logger.info(f"IPv6配置成功: {config['ipv6']}")
                else:
                    logger.error(f"IPv6配置失败: {error_msg}")
    except subprocess.CalledProcessError as e:
        error_msg = f"执行命令失败: {str(e)}, 返回码: {e.returncode}"
        logger.error(f"应用IP配置出错: {error_msg}")
        if hasattr(e, 'output') and e.output:
            logger.error(f"命令输出: {e.output}")
        if hasattr(e, 'stderr') and e.stderr:
            logger.error(f"错误输出: {e.stderr}")
    except Exception as e:
        error_msg = f"应用配置时出错: {str(e)}"
        logger.error(f"应用IP配置出错: {error_msg}")
        import traceback
        logger.error(f"详细错误信息: {traceback.format_exc()}")
        
    return success, error_msg