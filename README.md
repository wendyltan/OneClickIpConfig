# 一键配置电脑IP工具

一个用于快速配置Windows系统网络IP地址的图形化工具，支持IPv4和IPv6配置，提供简单直观的界面，方便网络管理员和普通用户快速切换网络配置。

## 功能特点

### 网络配置管理
- 自动识别并显示以太网卡的详细信息（仅物理网卡）
- 显示当前IPv4和IPv6地址、子网掩码、网关、DNS和MAC地址
- 支持手动配置和自动获取（DHCP）两种模式
- 一键应用网络配置，无需手动操作系统设置

### Ping测试功能
- 快速测试网关连通性
- 快速测试DNS服务器连通性
- 支持自定义IP地址的Ping测试
- 可调节Ping包数量和大小
- 支持IPv4和IPv6网络测试

### 其他特性
- 直观的图形用户界面
- 实时日志显示
- 管理员权限自动请求
- 详细的操作反馈

## 系统要求

- Windows 7/8/10/11 操作系统
- 管理员权限（修改网络配置需要）
- Python 3.7+（源码运行时需要）

## 安装使用

### 预编译版本

1. 从[发布页面](https://github.com/yourusername/OneClickIP/releases)下载最新版本的可执行文件
2. 右键点击程序，选择"以管理员身份运行"
3. 按照界面提示操作

### 从源码运行

1. 克隆或下载本仓库
```
git clone https://github.com/yourusername/OneClickIP.git
```

2. 安装依赖
```
pip install PyQt5
```

3. 以管理员身份运行程序
```
python main.py
```

## 打包说明

本项目使用PyInstaller进行打包，支持32位和64位Windows系统。

### 32位系统打包
```
pyinstaller --onefile --windowed --upx-dir="path\to\upx" --clean main.py
```

### 64位系统打包
```
pyinstaller --onefile --windowed --upx-dir="path\to\upx" --clean main.py
```

## 项目结构

- `main.py` - 主程序入口和GUI实现
- `ip_config.py` - IP配置相关功能
- `network_utils.py` - 网络工具函数
- `log_config.py` - 日志配置
- `apply_config.py` - 应用配置的实现

## 贡献指南

1. Fork 本仓库
2. 创建您的特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交您的更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 打开一个 Pull Request

## 许可证

本项目采用 MIT 许可证 - 详情请参阅 [LICENSE](LICENSE) 文件

## 联系方式

如有问题或建议，请通过以下方式联系：

- 项目Issues: [https://github.com/yourusername/OneClickIP/issues](https://github.com/yourusername/OneClickIP/issues)
- 邮箱: your.email@example.com

## 致谢

- 感谢所有为本项目做出贡献的开发者
- 感谢PyQt5提供的GUI框架