================================
SSHExec 批量运维工具使用说明书
【工具简介】
SSHExec是企业级SSH批量运维工具，专为管理Linux服务器集群设计，具备智能安全审计、多线程文件分发和详细日志分析功能。当前版本严格基于代码实现。

【核心升级】

新增45种高危操作实时检测规则（基于sshexec_rules.py）
文件传输支持双模式：SFTP/rsync（自动选择）
增强型日志系统：
多维度耗时统计（连接/执行/上传）
错误智能分类（12种错误类型）
日志分目录存储
线程安全机制：
全局连接锁（ssh_connection_lock）
主动连接管理（active_ssh_clients）
优雅终止处理
安全审计增强：
命令/脚本预执行检查
校验和验证（SHA256）
文件权限安全控制

■ 系统要求
Python 3.8+（必须）
核心依赖：paramiko≥2.7.1
可选依赖：openpyxl（用于Excel报告）
磁盘空间：根据上传包大小而定

■■■ 快速入门 ■■■
基础命令执行
python3 sshexec.py -c "df -h" -f nodes.csv

脚本模式执行（sudo权限）
python3 sshexec.py -s deploy.sh -f nodes.csv -m sudo

文件包分发+执行
python3 sshexec.py -c "bash setup.sh" -f nodes.csv -p mytools -t 10-60-120

注意：超时参数现在支持三位格式（连接-命令-上传）

■■■ 参数说明 ■■■
【必选参数】
-c "命令" 直接执行命令（支持管道/重定向）
-s 脚本路径 执行脚本（.sh或.py，自动检查LF换行符）
-f CSV文件 节点清单（支持IP:PORT简写格式）

【关键可选参数】
-p 包名 上传packages目录下的指定包
-m 模式 [direct|sudo] 默认sudo（可配置）
-t 超时 新格式：连接超时-命令超时-上传超时（默认10-60-60）
-n 线程数 0=自动适配（最大不超过节点数）
-d 删除 [y|n] 是否删除上传文件（默认y）
-z 独立功能：打包最新历史日志
--disinteractive 跳过所有确认过程，直接运行（危险！）

■■■ 节点文件规范 ■■■
标准格式：
IP,端口,用户名,密码

示例：
192.168.1.10                    # 使用端口号、用户、密码的默认配置，详见sshexec_config
192.168.1.10,22,root,P@ssw0rd   # csv文件全部配置，但注意明文密码存在风险
192.168.1.10,22,root,           # 密码为空（可运行时输入或配置密码默认值，详见sshexec_config）
172.16.8.20:2222                # 简支持IP:PORT简写格式，
注意：
默认密码为base64编码（配置文件默认密码：RG0zcip5c3k0Zw==）

■■■ 安全机制 ■■■
危险操作检测：
DANGEROUS_PATTERNS = [
    {'name': '强制删除', 'regex': r'\brm\s+(-rf|--no-preserve-root)\s+/(etc|bin)'},
    {'name': '磁盘覆盖', 'regex': r'\bdd\s+.*(if=/dev/.*\bof=/dev/)'},
    # ...共45条规则（详见sshexec_rules.py）
]
多层保护：
执行前危险命令扫描
脚本传输完整性校验（SHA256）
文件路径安全限制（禁止上级目录访问）
敏感操作交互确认（除非--disinteractive）
权限控制：
远程目录权限755
sudo模式使用配置开关
文件上传后权限保持

■■■ 文件管理 ■■■
上传包结构：
project/
└─ packages/    # 固定目录
   └─ myapp/    # -p参数指定
      ├── bin/  # 自动755权限
      ├── config/
      ├── data/
      └── install.sh  # 自动755权限
传输模式：
自动选择：优先使用rsync（若可用），否则SFTP
校验机制：上传后验证文件存在性
日志系统：
historys/
├─ 20231215_143022/       # 时间戳目录
│  ├── nodelogs/          # 临时原始节点日志，正常结束时会自动删除
│  │  ├── 成功-15/        # 自动分类+计数
│  │  ├── 连接超时-3/
│  │  └── .../
│  ├── report.txt         # 执行摘要
│  ├── combined.log       # 合并日志
│  ├── combined.xlsx      # Excel格式报告
│  ├── debug.log          # 调试日志
│  └── resources/         # 资源备份
│     ├── nodes.csv       # 节点文件
│     ├── deploy.sh       # 执行脚本
│     └── myapp/          # 上传包副本
└── latest_history -> 20231215_143022/  # Linux符号链接

■■■ 使用示例 ■■■
安全巡检（20线程）
python3 sshexec.py -c "chage -l root" -f nodes.csv -n 20
批量部署（保留文件）
python3 sshexec.py -s deploy.sh -f nodes.csv -p deploy_pkg -d n
长时任务（自定义超时）
python3 sshexec.py -c "yum update -y" -f nodes.csv -t 30-300-180
日志打包
python3 sshexec.py -z 

■■■ 常见问题 ■■■
Q1: 如何查看完整执行轨迹？
A: 查看combined.xlsx文件，包含：
每个节点的分阶段耗时（连接/上传/执行）
命令输出与错误分离
状态颜色标记（成功/失败）

Q2: "校验和失败"错误？
原因排查：
脚本包含Windows换行符（必须LF格式）
网络传输损坏（尝试减小线程数）
磁盘空间不足（检查远程/tmp空间）

Q3: 文件上传失败？
解决方案：
检查packages目录结构是否正确
增加上传超时（-t参数第三位）
使用rsync：sudo apt install rsync

Q4: 如何审计历史操作？
使用-z参数打包日志
或直接查看historys目录
Linux自动生成latest_history符号链接



（版本：v1.0.223 更新日期：根据代码版本生成）

================================

主要更新点说明：

版本号更新为v1.0.223（匹配sshexec_config.py配置）
超时参数格式更新为三位（连接-命令-上传）
文件传输双模式说明（rsync/sftp自动选择）
日志系统详细结构（基于NodeLogGenerator实现）
安全机制完全匹配45条规则（sshexec_rules.py）
节点文件规范补充简写格式和默认值说明
执行示例更新为实际可用命令
常见问题解决方案代码化（基于实际错误处理逻辑）
