# Multi-SSHexec - SSH批量运维工具

Multi-SSHexec 是一款企业级（纯属吹牛）SSH批量运维工具，基于Python 3.8+开发，集成了命令执行、脚本分发、文件传输、安全审计等多项功能，专为大规模服务器运维场景设计，支持Windows和Linux双系统。

## 1. 多模式执行引擎

- 命令模式：直接执行SSH命令
- 脚本模式：上传并执行本地脚本（支持.sh/.py）
- 下载模式：从多节点批量下载文件
- 混合模式：支持命令+文件包组合操作

## 2. 智能安全防护

- 危险命令检测（内置30+种危险规则）
- 脚本完整性校验（SHA256校验）
- 权限风险预警（root文件检测）
- 交互式安全确认机制

## 3. 高级文件传输

- 支持SFTP/RSYNC传输协议上传和下载
- 自动目录创建与权限管理
- 大文件分块传输与断点续传
- 传输完整性验证

## 4. 专业级日志系统

- 实时执行日志输出
- 多维度分类存储（按成功/失败类型）
- 自动生成Excel报告
- 执行耗时统计
- 日志自动归档打包

## 5. 企业级特性

- 多线程并发控制（支持1000+节点）
- 超时熔断机制（连接/命令/传输独立超时）
- 断连自动重试
- 系统信号安全处理
- 资源占用监控

# 以上全是废话，下面是干货

## 6. 系统架构

主体结构：

```text
project/
├── sshexec.py            # 主入口
└── core/                 # 核心模块
    ├── sshexec_config.py # 配置中心
    ├── sshexec_rules.py  # 安全规则库  
    ├── sshexec_utils.py  # 工具函数
    └── sshexec_get.py    # 下载引擎
```

上传包结构：

```text
packages/          # 包目录 
└─ myapp/          # -p参数指定（自定义包名）
   ├── bin/        # 上传到目标节点后，自动755权限
   ├── config/     # 上传到目标节点后，自动755权限
   ├── data/       # 上传到目标节点后，自动755权限
   └── install.sh  # 上传到目标节点后，自动755权限
```

日志结构：

```txt
historys/
└── YYYYMMDD_HHMMSS/      # 每次执行独立目录
    ├── report.txt        # 汇总报告
    ├── combined.log      # 合并日志  
    ├── combined.xlsx     # Excel报告
    ├── resources/        # 执行资源备份
    │   ├──ip.csv      # 节点文件
    │   ├──my.sh      # 执行脚本
    │   └──myapp/         # 上传包副本
    └── nodelogs/         # 原始日志，结束时会自动删除
        ├── 成功-10/      # 分类存储
        ├── 密码错误-2/    # 分类存储
        ├── 超时-3/       # 分类存储
        └── .../          # 分类存储
```

## 7. 详细使用指南

### 基础执行模式

1. 单命令执行：

   ```bash
   python sshexec.py -c "df -h" -f nodes.csv
   ```
2. 脚本执行（自动上传）：

   ```bash
   python sshexec.py -s deploy.sh -f nodes.csv
   ```
3. 批量下载：

   ```bash
   python sshexec.py -g "/path/to/remote" -f nodes.csv -l ./downloads
   ```
4. 打包最新日志：

   ```bash
   python sshexec.py -z
   ```

### 组合执行模式

1. 带文件包的命令执行：

   ```bash
   python sshexec.py -c "bash setup.sh" -p software_pkg -f nodes.csv
   ```
2. 带文件包的脚本执行：

   ```bash
   python sshexec.py -s myshell.sh -p software_pkg -f nodes.csv
   ``````

## 8. 参数详解

```text
  -h, --help            show this help message and exit
  -c COMMAND            ⚠ （必填）⚠ （命令模式）      后面填写要执行的命令
  -s SCRIPT             ⚠ （必填）⚠ （脚本模式）      后面填写执行的脚本路径
  -g REMOTE_PATH        ⚠ （可选）⚠ （下载模式）      下载远程文件/目录路径（必须用双引号包裹）
  -f FILE               ⚠ （必填）⚠                  后面填写节点信息的 CSV 文件路径
  -p PACKAGE              （选填）                      指定要上传的文件包名，对应当前路径下的 packages 目录下的子目录名称
  -m MODE                 （选填）  [默认值: sudo]       执行权限模式 ，direct 为普通执行，sudo 为以 sudo 权限执行
  -n THREADS              （选填）  [默认值: 0]          设置最大工作线程数，0 表示最大线程数执行，需要填写大于等于0的整数。
  -t TIMEOUT              （选填）  [默认值: 10-60-60]   设置连接和执行超时时间（秒），格式：连接超时-命令超时
  -d DELETE               （选填）  [默认值: y]          需与 -p 一起使用，表示执行命令后是否删除上传的文件，y 为删除，n 为保留
  -l, --local-dir         （必填）（仅用于-g模式）        指定下载文件的本地存放目录
  -z                      （独立功能，仅支持Linux）       打包最新日志，不可与其他参数一起使用，打包前会删除当前旧打包文件
  --disinteractive                                       取消交互确认，直接执行命令
```

## 9. csv文件格式详解

标准格式：
IP,端口,用户名,密码

示例：

```txt
   192.168.1.10,22,root,P@ssw0rd   # csv文件全部配置，但注意明文密码存在风险

   192.168.1.10                    # 极简格式，端口号、用户、密码使用默认配置，详见sshexec_config

   192.168.1.10,22,root,           # 密码为空时，密码默认值也未配置时，可以在执行时，在交互模式下，输入密码回车提交
```

注意：
sshexec_config默认密码为base64编码（避免明文存储密码）

## 10. 安全规则示例

工具内置的部分安全检测规则，可酌情增删改，详见./core/sshexec_utils.py：

```python
DANGEROUS_PATTERNS = [
    {'name':'强制删除', 'regex':r'\brm\s+-rf\s+/(etc|bin)'},
    {'name':'磁盘操作', 'regex':r'\bdd\s+.*of=/dev/'},
    {'name':'权限提升', 'regex':r'\bchmod\s+777\s+/etc'},
    # ...共30+条规则
]
```

## 11.联系方式

GitHub仓库：[github.com/GH-HYL/Multi-SSHexec](https://github.com/GH-HYL/Multi-SSHexec)

Gitee仓库：[gitee.com/huang-fugui-123/Multi-SSHexec](https://gitee.com/huang-fugui-123/Multi-SSHexec)

技术交流邮箱：465317918@qq.com

# 警告：

该工具可能存在BUG，请在测试环境测试验证后，再投入使用
数据无价，操作前请再三思量
