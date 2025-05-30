import logging
import os
import sys
import io

# 创建一个内存日志处理器，用于在GUI中显示日志
class MemoryHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.log_buffer = io.StringIO()
        self.formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        # 添加一些初始日志内容，确保缓冲区不为空
        self.log_buffer.write("--- 日志系统初始化 ---\n")
    
    def emit(self, record):
        try:
            msg = self.formatter.format(record)
            self.log_buffer.write(msg + '\n')
        except Exception as e:
            # 确保emit方法不会因为异常而中断日志处理
            self.log_buffer.write(f"日志处理错误: {str(e)}\n")
    
    def get_logs(self):
        try:
            return self.log_buffer.getvalue()
        except Exception as e:
            # 如果获取日志内容失败，返回错误信息
            return f"获取日志内容失败: {str(e)}\n"

# 创建全局内存处理器实例
memory_handler = MemoryHandler()

def setup_logging():
    """配置日志系统"""
    # 创建日志文件路径
    log_file_path = os.path.join(os.path.dirname(__file__), 'debug_ip_config.log')
    
    # 配置日志系统
    # 使用FileHandler而不是basicConfig，以便指定编码
    logger = logging.getLogger('ip_config')
    logger.setLevel(logging.INFO)  # 将日志级别设置为INFO，减少DEBUG级别的输出
    
    # 清除所有现有的处理器
    for handler in logger.handlers[:]: 
        logger.removeHandler(handler)
    
    # 添加内存处理器，用于在GUI中显示日志
    logger.addHandler(memory_handler)
    
    # 在调试模式下才添加控制台处理器
    # 正常运行时不添加控制台处理器，避免在CMD窗口显示日志
    if os.environ.get('DEBUG_MODE') == '1':
        console_handler = logging.StreamHandler()
        console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(console_formatter)
        console_handler.setLevel(logging.WARNING)  # 只输出警告和错误
        logger.addHandler(console_handler)
    
    try:
        # 创建FileHandler并指定编码为gbk
        file_handler = logging.FileHandler(log_file_path, mode='w', encoding='gbk')
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
        # 记录日志文件位置到日志文件中
        logger.info(f"日志文件保存在: {log_file_path}")
        logger.info("--- 日志开始 ---")
    except PermissionError:
        logger.warning(f"创建日志文件失败: [Errno 13] Permission denied: '{log_file_path}'，将只使用内存日志")
    except Exception as e:
        logger.warning(f"创建日志文件失败: {str(e)}，将只使用内存日志")
    
    return logger

# 创建全局logger对象
logger = setup_logging()

# 定义简化的日志函数，替代print
def log_debug(message):
    logger.debug(message)

def log_info(message):
    logger.info(message)

def log_warning(message):
    logger.warning(message)

def log_error(message):
    logger.error(message)

def log_critical(message):
    logger.critical(message)