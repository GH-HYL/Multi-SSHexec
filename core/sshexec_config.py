# -*- coding: utf-8 -*-

# SSHexec配置文件
VERSION = "1.0.223"
TOOL_NAME = "sshexec"
DEFAULT_SUDO_MODE = "sudo"              # sudo执行模式默认值 "direct" or "sudo"
DEFAULT_DELETE = "y"                    # 文件删除默认值 "y" or "n"
DEFAULT_CONN_TIMEOUT = 10               # 连接超时默认值 10秒
DEFAULT_CMD_TIMEOUT = 60                # 命令执行超时默认值 60秒
DEFAULT_UPLOAD_TIMEOUT = 60             # 文件上传超时默认值 60秒
CLEANUP_TIMEOUT = 60                    # -p上传临时文件的清理操作超时默认值 60秒
DEFAULT_CONCURRENT = 5                  #  (-g --get 专用) 默认并发线程数 5
DOWNLOAD_TIMEOUT = 300                  #  (-g --get 专用) 下载操作超时(秒)
DEFAULT_TIMEOUT = f"{DEFAULT_CONN_TIMEOUT}-{DEFAULT_CMD_TIMEOUT}-{DEFAULT_UPLOAD_TIMEOUT}" 
# DEFAULT_TIMEOUT = f"{DEFAULT_CONN_TIMEOUT}-{DEFAULT_CMD_TIMEOUT}-{DEFAULT_UPLOAD_TIMEOUT}-{DOWNLOAD_TIMEOUT}"

# CSV文件相关配置
DEFAULT_IP_PORT = "10022"              # CSV文件默认IP端口 10022
DEFAULT_USER = "jx_zyc"                 # CSV文件默认用户名
DEFAULT_PASSWORD = "RG0zcip5c3k0Zw=="   # CSV文件默认密码（base64编码后的字符串） # 可以为空→"",为空后csv仍然未配置密码，可以通过命令行参数传入密码

# 颜色配置
COLOR_GREEN = "\033[32m"                # 绿色
COLOR_RED = "\033[31m"                  # 红色
COLOR_CYAN = "\033[36m"                 # 青色
COLOR_YELLOW = "\033[33m"               # 黄色
COLOR_RESET = "\033[0m"                 # 重置颜色
