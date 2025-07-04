# -*- coding: utf-8 -*-
# 已移除debug
# 项目目录/
# ├── sshexec.py            # 主程序
# └── core/                 # 配置和规则目录
#     ├── sshexec_config.py # 自定义配置文件
#     ├── sshexec_utils.py  # 工具函数文件  
#     └── sshexec_rules.py  # 警告规则文件

import paramiko
import os
import shutil
import sys
import io
import platform
import posixpath
import re
import zipfile
import tarfile
import shlex
import hashlib
import socket
import time
import traceback
import getpass
import signal
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# 导入配置和规则
from core.sshexec_config import (
    TOOL_NAME, DEFAULT_SUDO_MODE, DEFAULT_DELETE,
    DEFAULT_CONN_TIMEOUT, DEFAULT_CMD_TIMEOUT, DEFAULT_UPLOAD_TIMEOUT,
    CLEANUP_TIMEOUT, DEFAULT_CONCURRENT,DOWNLOAD_TIMEOUT,
    COLOR_GREEN, COLOR_RED, COLOR_CYAN, 
    COLOR_YELLOW, COLOR_RESET
)

from core.sshexec_rules import (
    DANGEROUS_PATTERNS
)

# 导入函数
from core.sshexec_utils import check_dependencies
from core.sshexec_utils import create_latest_log_symlink
from core.sshexec_utils import rename_nodelog_folders
from core.sshexec_utils import convert_combined_log_to_xlsx
from core.sshexec_utils import merge_nodelogs_to_combined
from core.sshexec_utils import read_nodes
from core.sshexec_utils import parse_args


# 全局变量
active_ssh_clients = []      
active_ssh_lock = threading.Lock()  
shutdown_event = threading.Event()
ssh_connection_lock = threading.Lock()  

class Config:
    def __init__(self, command='', conn_timeout=DEFAULT_CONN_TIMEOUT, 
                 cmd_timeout=DEFAULT_CMD_TIMEOUT, upload_timeout=DEFAULT_UPLOAD_TIMEOUT, 
                 mode='cmd', script_path=None, sudo_mode=DEFAULT_SUDO_MODE,
                 package=None, delete=DEFAULT_DELETE, log_base=''):
        self.command = command
        self.conn_timeout = conn_timeout
        self.cmd_timeout = cmd_timeout
        self.upload_timeout = upload_timeout
        self.mode = mode
        self.script_path = script_path.replace("\\", "/") if script_path else None
        self.sudo_mode = sudo_mode
        self.package = package
        self.delete = delete
        self.log_base = log_base

class SecurityCheckError(ValueError):
    def __init__(self, issues):
        self.issues = issues
        super().__init__("检测到危险命令")
        
class SSHResult:
    def __init__(self):
        self.interrupted = False
        self.start_time = datetime.now()  
        self.end_time = None
        self.duration = None
        self.success = False
        self.error_type = None
        self.directory_status = {}
        self.file_transfers = []
        self.cleanup_status = {}
        self.output_lines = []
        self.error_lines = []
        self.upload_success = False
        self.sanitized_path = ""
        self.script_path = None
        self.conn_timeout = None
        self.cmd_timeout = None
        self.command_exec = {} 

class ExecutionResult:
    def __init__(self):
        self.start_time = datetime.now()
        self.command = ""
        self.mode = ""
        self.sudo_mode = "direct"

class NodeLogGenerator:
    PHASE_TEMPLATES = {
        'connection': {
            'success': {"msg": "[连接建立] SSH连接成功建立"},
            'timeout': {"msg": "[连接超时] {duration}秒内未响应"},
            'auth_fail': {"msg": "[认证失败] 用户名/密码错误"},
            'ssh_error': {"msg": "[SSH错误] {error}"},
            'other_errors': {"msg": "[连接错误] {error}"}
        },
        'directory': {
            'create': {"msg": "[目录创建] 已创建远程目录：{path}"},
            'exists': {"msg": "[目录准备] 远程目录已就绪：{path}"},
            'fail': {"msg": "[目录错误] 创建失败：{error}"}
        },
        'file_transfer': {
            'start': {"msg": "[文件传输] 开始上传：{local} → {remote}"},
            'method': {"msg": "[上传方式] {method}"}, 
            'uploading': {"msg": "[文件上传] 正在上传文件：{local} → {remote}"},
            'timeout': {"msg": "[上传超时] 超过{timeout}秒未完成"}, 
            'success': {"msg": "[文件上传] 文件上传成功"},
            'verify': {"msg": "[文件验证] 远程文件存在确认：{path}"},
            'missing': {"msg": "[文件验证] 缺失文件：{path}"},
            'verified': {"msg": "[文件验证] 远程文件存在确认：{path}"}
        },
        'execution': {
            'prepare': {"msg": "[命令执行] 执行脚本：{script}"},
            'exit_code': {"msg": "[执行结果] 退出码：{code}"},
            'output': {"msg": "[输出收集] 收集到 {lines} 行标准输出，{errors} 行错误输出"},
            'password_expired': {"msg": "[密码检查] 检测到密码过期提示"},
            'timeout': {"msg": "[执行超时] {timeout}秒内未完成"}
        },
        'cleanup': {
            'start': {"msg": "[清理操作] 开始删除远程目录：{path}"},
            'success': {"msg": "[清理操作] 远程目录已删除：{path}"},
            'fail': {"msg": "[清理操作] 删除失败：{error}"}
        },
        'closure': {
            'complete': {"msg": "[连接关闭] 已完成对 {ip} 的处理"}
        }
    }
    def __init__(self, ip, ssh_result, command=None, package=None, script_path=None):
        if not isinstance(ssh_result, SSHResult):
            raise TypeError("需要SSHResult实例")
        self.ip = ip
        self.result = ssh_result
        self.command = command
        self.package = package
        self.script_path = script_path
        self.log_buffer = []
        self.success = ssh_result.success
        self.error_type = ssh_result.error_type

    def _should_log(self, entry_type):
        return True

    def generate_formatted_logs(self):
        self._add_time_header()
        self._process_connection_phase()

        if self.package and not self.result.directory_status and hasattr(self.result, 'sanitized_path'):
            self.result.directory_status = {
                'path': self.result.sanitized_path,
                'exists': True
            }

        if self.error_type and not self.log_buffer:
            self.log_buffer.append(f"【{self.ip}】[错误摘要] {self.error_type}")
    
        self._process_directory_phase()
        self._process_file_transfer()
        self._process_execution()
        self._process_cleanup()
    
        log_content = "\n".join(self.log_buffer)
        return log_content if log_content else f"【{self.ip}】[空日志] 节点处理无任何输出（可能提前终止）"

    def _add_time_header(self):
        self.log_buffer.append("=" * 80)
        try:
            if self.result.duration is None:
                self.result.duration = datetime.now() - self.result.start_time
            duration_seconds = self.result.duration.total_seconds()
        except Exception:
            duration_seconds = 0.0
        start_str = self.result.start_time.strftime('%Y-%m-%d %H:%M:%S')
        end_str = self.result.end_time.strftime('%Y-%m-%d %H:%M:%S') if self.result.end_time else '未知时间'
        time_header = f"时间: 开始 {start_str} 结束 {end_str} 耗时: {duration_seconds:.2f} 秒"
        self.log_buffer.append(f"【{self.ip}】{time_header}")

    def _process_connection_phase(self):
        if self.result.error_type == 'connection_timeout':
            entry_type = self.PHASE_TEMPLATES['connection']['timeout']
            entry = entry_type['msg'].format(duration=self.result.conn_timeout)
            self.log_buffer.append(f"【{self.ip}】{entry}")
        elif self.result.error_type == 'authentication_failed':
            entry_type = self.PHASE_TEMPLATES['connection']['auth_fail']
            entry = entry_type['msg']
        elif self.result.error_type == 'ssh_error':
            entry_type = self.PHASE_TEMPLATES['connection']['ssh_error']
            entry = entry_type['msg'].format(error=self.result.status or "SSH连接异常")
        elif self.result.error_type in ['port_unreachable', 'other_errors']:
            entry_type = self.PHASE_TEMPLATES['connection']['other_errors']
            entry = entry_type['msg'].format(error=self.result.status or "连接失败")
        else:
            entry_type = self.PHASE_TEMPLATES['connection']['success']
            entry = entry_type['msg']

        self.log_buffer.append(f"【{self.ip}】{entry}")

    def _process_directory_phase(self):
        dir_status = self.result.directory_status
        if not dir_status or not self.package:
            return

        dir_status = self.result.directory_status
        if dir_status.get('created'):
            entry_type = self.PHASE_TEMPLATES['directory']['create']
            entry = entry_type['msg'].format(path=dir_status['path'])
        elif dir_status.get('exists'):
            entry_type = self.PHASE_TEMPLATES['directory']['exists']
            entry = entry_type['msg'].format(path=dir_status['path'])
        elif dir_status.get('error'):
            entry_type = self.PHASE_TEMPLATES['directory']['fail']
            entry = entry_type['msg'].format(error=dir_status['error'])
            self.error_type = 'ssh_error'
        else:
            return

        self.log_buffer.append(f"【{self.ip}】{entry}")

    def _process_file_transfer(self):

        if self.package and self.result.upload_success:
            upload_method = getattr(self.result, 'upload_method', 'sftp')

            entry_type = self.PHASE_TEMPLATES['file_transfer']['start']
            entry = entry_type['msg'].format(local=self.package, remote=self.result.sanitized_path)
            self.log_buffer.append(f"【{self.ip}】{entry}")
            upload_method = getattr(self.result, 'upload_method', 'sftp')
            self.log_buffer.append(f"【{self.ip}】[上传方式] 使用{upload_method}上传")
            
            for transfer in self.result.file_transfers:
                if transfer['status'] == 'timeout':
                    entry_type = self.PHASE_TEMPLATES['file_transfer']['timeout']
                    entry = entry_type['msg'].format(timeout=self.result.upload_timeout)
                    self.log_buffer.append(f"【{self.ip}】{entry}")
                    self.error_type = 'upload_timeout' 
                if transfer['status'] == 'uploading':
                    entry_type = self.PHASE_TEMPLATES['file_transfer']['uploading']
                    entry = entry_type['msg'].format(**transfer)
                elif transfer['status'] == 'success':
                    entry_type = self.PHASE_TEMPLATES['file_transfer']['success']
                    entry = entry_type['msg'].format(**transfer)
                elif transfer['status'] == 'missing':
                    entry_type = self.PHASE_TEMPLATES['file_transfer']['missing']
                    entry = entry_type['msg'].format(**transfer)
                    self.error_type = 'ssh_error'
                elif transfer['status'] == 'verified':
                    entry_type = self.PHASE_TEMPLATES['file_transfer']['verified']
                    entry = entry_type['msg'].format(**transfer)
                else:
                    continue

                self.log_buffer.append(f"【{self.ip}】{entry}")

    def _process_execution(self):
        if not self.result.command_exec:
            return
        self._add_execution_prepare_log()
        self._add_exit_code_log()
        self._add_common_output_logs()
    
        if self.error_type == 'command_timeout':
            entry_type = self.PHASE_TEMPLATES['execution']['timeout']
            entry = entry_type['msg'].format(timeout=self.result.cmd_timeout)
            self.log_buffer.append(f"【{self.ip}】{entry}")

    def _add_execution_prepare_log(self):
        try:
            if self.package:
                entry = f"[命令执行] 切换到上传目录 {self.result.sanitized_path} 后执行：{self.command}"
            elif self.script_path:
                entry_type = self.PHASE_TEMPLATES['execution']['prepare']
                script_name = os.path.basename(self.script_path)
                entry = entry_type['msg'].format(script=script_name)
            elif self.command:
                entry = f"[命令执行] {self.command}"
            else:
                entry_type = self.PHASE_TEMPLATES['execution']['prepare']
                entry = entry_type['msg'].format(script="未知脚本")

            self.log_buffer.append(f"【{self.ip}】{entry}")
        except Exception as e:
            error_msg = f"日志生成异常: {str(e)}"
            self.log_buffer.append(f"【{self.ip}】[日志错误] {error_msg}")

    def _add_password_expired_log(self):
        entry_type = self.PHASE_TEMPLATES['execution']['password_expired']
        entry = entry_type['msg']
        self.log_buffer.append(f"【{self.ip}】{entry}")

    def _add_exit_code_log(self):
        entry_type = self.PHASE_TEMPLATES['execution']['exit_code']
        entry = entry_type['msg'].format(code=self.result.command_exec['exit_code'])
        self.log_buffer.append(f"【{self.ip}】{entry}")

    def _process_cleanup(self):
        if not self.package or not self.result.cleanup_status:
            return
        
        cleanup = self.result.cleanup_status
        if 'start' in cleanup:
            entry_type = self.PHASE_TEMPLATES['cleanup']['start']
            entry = entry_type['msg'].format(path=cleanup['path'])
            self.log_buffer.append(f"【{self.ip}】{entry}")
        
        if 'success' in cleanup:
            entry_type = self.PHASE_TEMPLATES['cleanup']['success']
            entry = entry_type['msg'].format(path=cleanup['path'])
            self.log_buffer.append(f"【{self.ip}】{entry}")
        elif 'fail' in cleanup:
            entry_type = self.PHASE_TEMPLATES['cleanup']['fail']
            entry = entry_type['msg'].format(error=cleanup.get('error', '未知错误'))
            self.log_buffer.append(f"【{self.ip}】{entry}")

    def _add_common_output_logs(self):
        if self.result.error_type == 'checksum_mismatch':
            self.log_buffer.append(f"【{self.ip}】{COLOR_RED}安全警报：脚本传输完整性校验失败！{COLOR_RESET}")

        for line in self.result.error_lines:
            if "Traceback" not in line and "File \"" not in line:
                self.log_buffer.append(f"【{self.ip}】错误输出：{line}")

        for line in self.result.output_lines:
            self.log_buffer.append(f"【{self.ip}】》》{line}")


def upload_files(sftp, local_path, remote_path, result, upload_timeout, upload_method='sftp'):  
    import subprocess

    start_time = time.time() 
    total_end_time = start_time + upload_timeout
    result.file_transfers.append({'status': 'start','local': local_path,'remote': remote_path})

    try:
        result.upload_method = upload_method
        
        if upload_method == 'rsync':
            remote_host = f"{result.ssh_user}@{result.ssh_ip}:{remote_path}"
            rsync_cmd = [
                'rsync', '-avz', '--progress', '--timeout', str(upload_timeout),
                '--rsh', f'ssh -p {result.ssh_port}',  
                local_path + '/', remote_host
            ]
            
            result.file_transfers.append({
                'status': 'command', 
                'command': ' '.join(rsync_cmd)
            })
            
            
            try:
                result.file_transfers.append({'status': 'uploading','local': local_path,'remote': remote_path})
                subprocess.run(rsync_cmd, check=True, timeout=upload_timeout)
                result.file_transfers.append({'status': 'success'})
                return True
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                result.file_transfers.append({'status': 'fail','error': str(e)})
                return False
        else:
            for item in os.listdir(local_path):
                if time.time() > total_end_time: 
                    raise TimeoutError(f"文件上传超过{upload_timeout}秒，已中断")
                local_item = os.path.join(local_path, item)
                remote_item = posixpath.join(remote_path, item)
    
                if os.path.isfile(local_item):
                    result.file_transfers.append({'status': 'uploading','local': local_item,'remote': remote_item})
    
                    try:
                        def upload_callback(sent, total):
                            pass  
                        sftp.put(local_item, remote_item, callback=upload_callback) 
                    except Exception as e:
                        if "No space left on device" in str(e):
                            result.error_type = 'disk_full'
                            result.status = f"磁盘空间不足: {str(e)}"
                            result.file_transfers.append({'status': 'fail','error': str(e)})
                            raise
                        else:
                            result.file_transfers.append({'status': 'fail','error': str(e)})
                            raise
                    result.file_transfers.append({'status': 'success','local': local_item,'remote': remote_item})
    
                    try:
                        sftp.stat(remote_item)
                        result.file_transfers.append({'status': 'verified','path': remote_item})
                    except Exception as e:
                        result.file_transfers.append({'status': 'missing','path': remote_item,'error': str(e)})
                        print(f"文件验证失败: {remote_item}, 错误信息: {str(e)}")
                        raise
                elif os.path.isdir(local_item):
                    ensure_remote_dir_exists(sftp, remote_item, result)
                    upload_files(sftp, local_item, remote_item, result, upload_timeout)  
    except TimeoutError as e:
        result.error_type = 'upload_timeout'
        result.status = str(e)
        result.file_transfers.append({'status': 'timeout','error': f"上传超时（已用时间: {time.time()-start_time:.1f}秒）"})
        raise
    except Exception as e:
        if result.error_type != 'disk_full':
            result.file_transfers.append({'status': 'fail','error': str(e)})
            print(f"文件上传失败: {local_path} -> {remote_path}, 错误信息: {str(e)}")
        raise



def ensure_remote_dir_exists(sftp, remote_dir, result):
    try:
        sftp.stat(remote_dir)
        result.directory_status = {'path': remote_dir, 'exists': True}
    except FileNotFoundError:
        parent_dir = posixpath.dirname(remote_dir)
        if parent_dir != remote_dir:
            ensure_remote_dir_exists(sftp, parent_dir, result)
        sftp.mkdir(remote_dir, mode=0o755) 
        result.directory_status = {'path': remote_dir, 'created': True}
    return result

def remove_dir(sftp, path, result):
    result.cleanup_status = {'path': path,'start': True,'files': [],'dirs': []}
    def fix_permissions(sftp, path):
        try:
            sftp.chmod(path, 0o755) 
        except Exception as e:
            print(f"权限修正失败: {path} - {str(e)}")

    try:
        for item in sftp.listdir(path):
            itempath = posixpath.join(path, item)
            if sftp.stat(itempath).st_mode & 0o40000: 
                remove_dir(sftp, itempath, result)
                fix_permissions(sftp, itempath) 
            else:
                fix_permissions(sftp, itempath)  
                try:
                    sftp.remove(itempath)
                    result.cleanup_status['files'].append(itempath)
                except Exception as e:
                    error_msg = f"文件删除失败: {itempath} - {str(e)}"
                    print(error_msg)
                    result.cleanup_status['files'].append({
                        'path': itempath,
                        'error': error_msg
                    })

        try:
            sftp.rmdir(path)
            result.cleanup_status['dirs'].append(path)
        except Exception as e:
            error_msg = f"目录删除失败: {path} - {str(e)}"
            print(error_msg)
            result.cleanup_status['dirs'].append({
                'path': path,
                'error': error_msg
            })

        try:
            sftp.stat(path)
            raise Exception(f"目录 {path} 仍然存在")
        except FileNotFoundError:
            result.cleanup_status['verify'] = True
        except Exception as e:
            result.cleanup_status['verify_fail'] = str(e)
            print(f"目录删除验证失败: {path}, 错误信息: {str(e)}")
            raise

    except Exception as e:
        error_msg = f"目录删除过程中发生未知错误: {str(e)}"
        print(error_msg)
        result.cleanup_status['unknown_error'] = error_msg
        raise

def upload_package(client, package, result, upload_timeout): 
    base_dir = os.path.abspath("packages")  
    user_path = os.path.normpath(package)   
    
    safe_path = os.path.join(base_dir, user_path)
    if not safe_path.startswith(base_dir + os.path.sep):
        result.error_type = "security_error"
        result.status = f"禁止访问上级目录: {package}"
        return False
    
    local_package_path = safe_path  

    sftp = client.open_sftp()
    try:
        stdin, stdout, stderr = client.exec_command("echo $HOME")
        home_dir = stdout.read().decode("utf-8").strip()
        remote_base = posixpath.join(home_dir, ".sshexec_packages")
        sanitized_remote_package = posixpath.normpath(package)  

        remote_full_path = posixpath.join(remote_base, sanitized_remote_package)
        sanitized_path = posixpath.normpath(remote_full_path)  

        ensure_remote_dir_exists(sftp, sanitized_path, result)
        upload_files(sftp, local_package_path, sanitized_path, result, upload_timeout) 

        missing_files = []
        for root, dirs, files in os.walk(local_package_path):
            for file in files:
                rel_path = os.path.relpath(root, local_package_path)
                remote_file = posixpath.join(sanitized_path, rel_path, file)
                try:
                    sftp.stat(remote_file)
                    result.file_transfers.append({"status": "verified", "path": remote_file})
                except Exception as e:
                    missing_files.append(remote_file)
                    result.file_transfers.append({"status": "missing", "path": remote_file})

        if missing_files:
            raise Exception(f"关键文件缺失：{', '.join(missing_files)}")

        result.upload_success = True
        result.sanitized_path = sanitized_path
        return True
    except TimeoutError as e: 
        result.error_type = 'upload_timeout'  
        result.status = str(e)
        return False
    except Exception as e:
        result.error_type = "ssh_error"
        result.status = str(e)
        return False
    finally:
        sftp.close()




def execute_command(client, command, mode, sudo_mode, result, timeout, traceback):
    password_expired_patterns = [r"WARNING: Your password has expired", r"Password change required",r"密码已过期", r"需要更改密码", r"口令已过期", r"当前密码必须更改"]
    compiled_patterns = [re.compile(p, re.IGNORECASE) for p in password_expired_patterns]

    def build_exec_command():
        cmd_parts = []
        if hasattr(result, 'sanitized_path') and result.sanitized_path:
            safe_path = shlex.quote(result.sanitized_path)
            cmd_parts.append(f"cd {safe_path}")
        exec_prefix = "sudo " if sudo_mode == "sudo" else ""
        if mode == "s":
            cmd_parts.append(f"{exec_prefix}bash -s --")
        else:
            cmd_parts.append(f"{exec_prefix}{command}")
        return " && ".join(cmd_parts) if cmd_parts else ""

    result.command_exec = {'command': command, 'mode': mode}
    if not command.strip() and mode != "s":
        raise ValueError("执行命令为空，无法继续")

    try:
        if mode == "s":
            script_path = result.script_path
            with open(script_path, 'r', encoding='utf-8') as f:
                script_content = f.read()
            if not script_content.endswith('\n'):
                script_content += '\n'
            checksum = hashlib.sha256(script_content.encode()).hexdigest()
        else:
            script_content = None

        transport = client.get_transport()
        channel = transport.open_session()
        channel.settimeout(timeout)
        full_command = build_exec_command()
        if mode == "s":
            full_command = f'echo "CHECKSUM:{checksum}" && {full_command}' 
        channel.exec_command(full_command)

        if mode == "s":
            channel.send(script_content.encode('utf-8'))
            channel.shutdown_write()

        stdout = []
        stderr = []
        start_time = time.time()
        exit_code = None
        checksum_match = False
        remote_checksum = None

        while True:
            if shutdown_event.is_set():
                channel.close()
                raise socket.timeout("操作被用户中断")
            if time.time() - start_time > timeout:
                raise socket.timeout(f"命令执行超时，已超过 {timeout} 秒")

            if channel.recv_ready():
                data = channel.recv(4096).decode('utf-8', errors='ignore')
                stdout.append(data)
            if channel.recv_stderr_ready():
                data = channel.recv_stderr(4096).decode('utf-8', errors='ignore')
                stderr.append(data)
            if channel.exit_status_ready():
                exit_code = channel.recv_exit_status()
                break
            time.sleep(0.05)

        result.output_lines = ''.join(stdout).splitlines()
        result.error_lines = ''.join(stderr).splitlines()
        result.command_exec['exit_code'] = exit_code

        if mode == "s":
            for line in result.output_lines:
                if line.startswith("CHECKSUM:"):
                    remote_checksum = line.split(":")[1].strip()
                    if remote_checksum == checksum:
                        checksum_match = True
                    break
            if not checksum_match:
                result.error_type = 'checksum_mismatch'
                result.status = f"脚本校验失败(本地:{checksum[:8]} 远程:{remote_checksum[:8]})" if remote_checksum else "未收到校验码"
                return -1

        result.command_exec['password_expired'] = False

        for line in result.error_lines:
            for pattern in compiled_patterns:
                if pattern.search(line):
                    result.command_exec['password_expired'] = True
                    result.error_type = 'password_expired'
                    return exit_code

        for line in result.output_lines:
            for pattern in compiled_patterns:
                if pattern.search(line):
                    result.command_exec['password_expired'] = True
                    result.error_type = 'password_expired'
                    return exit_code

        return exit_code

    except socket.timeout as e:
        result.command_exec['exit_code'] = -1
        result.error_lines = [f"命令执行超时: {timeout}秒"]
        result.error_type = 'command_timeout'
        return -1
    except paramiko.SSHException as e:
        result.command_exec['exit_code'] = -1
        result.error_lines = [str(e)]
        result.error_type = 'ssh_error'
        return -1
    except Exception as e:
        
        result.command_exec['exit_code'] = -1
        result.error_lines = [str(e)]
        result.error_type = 'other_errors'
        return -1



def cleanup_package(client, package, delete, result, config):
    if delete.lower() in ('y', 'yes'):
        try:
            sftp = client.open_sftp()
            remote_base = "~/.sshexec_packages"
            
            stdin, stdout, stderr = client.exec_command(f"echo {remote_base}")
            abs_path = stdout.read().decode("utf-8").strip()
            
            result.cleanup_status = {
                'path': abs_path,
                'start': True
            }
            
            if config.sudo_mode == 'sudo':
                cleanup_cmd = f"sudo rm -rf {shlex.quote(abs_path)}"
            else:
                cleanup_cmd = f"rm -rf {shlex.quote(abs_path)}"
            
            stdin, stdout, stderr = client.exec_command(cleanup_cmd, timeout=CLEANUP_TIMEOUT)
            exit_code = stdout.channel.recv_exit_status()
            
            if exit_code == 0:
                try:
                    sftp.stat(abs_path)
                    result.cleanup_status['error'] = "目录仍然存在"
                    result.cleanup_status['fail'] = True
                except FileNotFoundError:
                    result.cleanup_status['success'] = True
                except Exception as e:
                    result.cleanup_status['error'] = str(e)
                    result.cleanup_status['fail'] = True
            else:
                error_msg = stderr.read().decode().strip()
                result.cleanup_status['error'] = f"退出码 {exit_code}: {error_msg}"
                result.cleanup_status['fail'] = True
            
            sftp.close()
            return result.cleanup_status.get('success', False)
        except Exception as e:
            result.cleanup_status['error'] = str(e)
            result.cleanup_status['fail'] = True
            return False
    return True

def execute_ssh(ip, port, user, pwd, config, command, conn_timeout, cmd_timeout, upload_timeout, mode, script_path, sudo_mode, package, delete, log_base):
    if shutdown_event.is_set():
        result = SSHResult()
        result.error_type = 'user_abort'
        result.status = "用户主动终止操作"
        return result

    client = None
    result = SSHResult()
    result.start_time = datetime.now()
    result.conn_timeout = conn_timeout
    result.cmd_timeout = cmd_timeout

    try:
        client = paramiko.SSHClient()
        with ssh_connection_lock:
            active_ssh_clients.append(client)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(conn_timeout)
        try:
            sock.connect((ip, int(port)))
        except socket.timeout:
            result.error_type = 'connection_timeout'
            result.status = f"连接超时 ({conn_timeout}秒内无响应)"
            result.end_time = datetime.now()
            result.duration = result.end_time - result.start_time  
            sock.close()
            return result
        except (socket.error, socket.gaierror, ValueError) as e:  
            result.error_type = 'port_unreachable'
            result.status = f"端口 {port} 不可达或地址解析失败（错误：{str(e)}）" 
            result.end_time = datetime.now()
            result.duration = result.end_time - result.start_time
            
            sock.close()
            log_generator = NodeLogGenerator(ip=ip, ssh_result=result, command=command, package=package, script_path=script_path)
            log_dir = os.path.join(config.log_base, 'nodelogs', classify_error(result))
            os.makedirs(log_dir, exist_ok=True)
            with open(os.path.join(log_dir, f"{ip}.log"), 'w', encoding='utf-8') as f:
                f.write(log_generator.generate_formatted_logs())
            return result

        client = paramiko.SSHClient()
        with active_ssh_lock:
            active_ssh_clients.append(client)
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            ip, int(port),
            username=user, password=pwd,
            timeout=config.conn_timeout,  
            banner_timeout=config.conn_timeout
        )

        if package:
            result.ssh_ip = ip
            result.ssh_port = port
            result.ssh_user = user
            upload_success = upload_package(client, package, result, upload_timeout) 
            
            if not upload_success:
                if result.error_type == 'upload_timeout': 
                    result.status = f"文件上传超过{upload_timeout}秒"
                log_generator = NodeLogGenerator(ip=ip, ssh_result=result, command=command, package=package, script_path=script_path)
                log_dir = os.path.join(config.log_base, 'nodelogs', classify_error(result))
                os.makedirs(log_dir, exist_ok=True)
                with open(os.path.join(log_dir, f"{ip}.log"), 'w', encoding='utf-8') as f:
                    f.write(log_generator.generate_formatted_logs())
                return result

        if mode == "s":
            script_path = os.path.abspath(script_path).replace("\\", "/") 
            result.script_path = script_path
            if package and hasattr(result, 'sanitized_path'):
                safe_upload_dir = shlex.quote(result.sanitized_path)
                command = f"cd {safe_upload_dir}; {command}"
        else:
            if package and hasattr(result, 'sanitized_path'):
                safe_upload_dir = shlex.quote(result.sanitized_path)
                if config.sudo_mode == "sudo":
                    command = f"sudo bash -c 'cd {safe_upload_dir} && {command}'"
                else:
                    command = f"cd {safe_upload_dir}; {command}"

        try:
            exit_code = execute_command(
            client, command, mode, sudo_mode, 
            result, cmd_timeout, traceback  
        )
            if package:
                try:
                    sftp = client.open_sftp()
                    remote_base = "~/.sshexec_packages"
                    
                    stdin, stdout, stderr = client.exec_command(f"echo {remote_base}")
                    abs_path = stdout.read().decode("utf-8").strip()
                    
                    result.cleanup_status = {'path': abs_path,'start': True}
                    
                    if config.sudo_mode == 'sudo':
                        cleanup_cmd = f"sudo rm -rf {shlex.quote(abs_path)}"
                    else:
                        cleanup_cmd = f"rm -rf {shlex.quote(abs_path)}"
                    
                    stdin, stdout, stderr = client.exec_command(cleanup_cmd, timeout=CLEANUP_TIMEOUT)
                    exit_code = stdout.channel.recv_exit_status()
                    
                    if exit_code == 0:
                        try:
                            sftp.stat(abs_path)
                            result.cleanup_status['error'] = "目录仍然存在"
                            result.cleanup_status['fail'] = True
                        except FileNotFoundError:
                            result.cleanup_status['success'] = True
                        except Exception as e:
                            result.cleanup_status['error'] = str(e)
                            result.cleanup_status['fail'] = True
                    else:
                        error_msg = stderr.read().decode().strip()
                        result.cleanup_status['error'] = f"退出码 {exit_code}: {error_msg}"
                        result.cleanup_status['fail'] = True
                    
                    sftp.close()
                except Exception as e:
                    result.cleanup_status['error'] = str(e)
                    result.cleanup_status['fail'] = True
                
                if result.cleanup_status.get('fail'):
                    result.error_type = 'cleanup_failed'
                    result.status = "临时文件清理失败"
                    log_generator = NodeLogGenerator(ip=ip, ssh_result=result, command=command, package=package, script_path=script_path)
                    log_dir = os.path.join(config.log_base, 'nodelogs', classify_error(result))
                    os.makedirs(log_dir, exist_ok=True)
                    with open(os.path.join(log_dir, f"{ip}.log"), 'w', encoding='utf-8') as f:
                        f.write(log_generator.generate_formatted_logs())

            result.success = exit_code == 0
        except ValueError as e:
            if mode == "s" and "执行命令为空" in str(e):
                result.success = True  
                exit_code = 0
                result.command_exec['exit_code'] = exit_code
            else:
                raise
        except paramiko.SSHException as e:
            if "timed out" in str(e):
                result.error_type = 'command_timeout'
                result.status = f"命令执行超时 ({cmd_timeout}秒内无响应)"
            else:
                result.error_type = 'ssh_error'
                result.status = f"SSH传输错误: {str(e)}"
            log_generator = NodeLogGenerator(ip=ip, ssh_result=result, command=command, package=package, script_path=script_path)
            log_dir = os.path.join(config.log_base, 'nodelogs', classify_error(result))
            os.makedirs(log_dir, exist_ok=True)
            with open(os.path.join(log_dir, f"{ip}.log"), 'w', encoding='utf-8') as f:
                f.write(log_generator.generate_formatted_logs())
        except socket.timeout:
            result.error_type = 'connection_timeout'
            result.status = f"连接超时 ({conn_timeout}秒内无响应)"
            result.end_time = datetime.now()  
            result.duration = result.end_time - result.start_time  

            log_generator = NodeLogGenerator(ip=ip, ssh_result=result, command=command, package=package, script_path=script_path)
            log_dir = os.path.join(config.log_base, 'nodelogs', classify_error(result))
            os.makedirs(log_dir, exist_ok=True)
            with open(os.path.join(log_dir, f"{ip}.log"), 'w', encoding='utf-8') as f:
                f.write(log_generator.generate_formatted_logs())

    except paramiko.AuthenticationException:
        result.error_type = 'authentication_failed'
        result.status = "用户名/密码错误"
        result.end_time = datetime.now()  
        result.duration = result.end_time - result.start_time
        return result
    
    except paramiko.SSHException as e:
        result.error_type = 'ssh_protocol_error'
        result.status = "SSH协议错误" 
        if "Error reading SSH protocol banner" in str(e):
            result.status = "SSH协议不兼容或网络中断"
        
        result.end_time = datetime.now()
        result.duration = result.end_time - result.start_time
        return result
    
    except Exception as e:
        result.error_type = 'other_errors'
        result.status = f"未知错误: {str(e)}"
        result.end_time = datetime.now()
        result.duration = result.end_time - result.start_time
        return result

    finally:
        try:
            if client:
                with active_ssh_lock:  
                    if client in active_ssh_clients:
                        active_ssh_clients.remove(client)
        except Exception as e:
            pass
        if not hasattr(result, 'end_time') or result.end_time is None:
            result.end_time = datetime.now()
        result.duration = result.end_time - result.start_time
        try:
            if client and client.get_transport() and client.get_transport().is_active():
                client.close()
        except Exception as e:
            pass
        try:
            if 'sock' in locals() and sock and not sock._closed:
                sock.shutdown(socket.SHUT_RDWR)
                sock.close()
        except Exception as e:
            pass

        return result




def save_results(log_base, result, total, conn_timeout, cmd_timeout, upload_timeout, args): 
    from collections import defaultdict

    end_time = datetime.now()
    
    nodelog_dir = os.path.join(log_base, 'nodelogs')
    
    all_ips = set()
    success_ips = set()
    failure_details = defaultdict(list)

    for category in os.listdir(nodelog_dir):
        category_dir = os.path.join(nodelog_dir, category)
        if not os.path.isdir(category_dir):
            continue
        
        ips_in_category = set()
        for filename in os.listdir(category_dir):
            if filename.endswith('.log'):
                ip = filename[:-4]
                if ip not in all_ips:
                    ips_in_category.add(ip)
        
        all_ips.update(ips_in_category)
        
        if category == '成功':
            success_ips.update(ips_in_category)
        else:
            failure_details[category].extend(sorted(ips_in_category, key=lambda ip: tuple(map(int, ip.split('.')))))

    success_count = len(success_ips)
    failure_count = len(all_ips) - success_count
    total_count = success_count + failure_count
    
    if total_count != total:
        print(f"\033[91m严重错误: 统计总数不一致！CSV记录数={total} 实际处理数={total_count}\033[0m")
        sys.exit(1)

    with open(os.path.join(log_base, 'report.txt'), 'w', encoding='utf-8') as f:
        f.write(f"{'=' * 40} 执行报告 {'=' * 40}\n")
        f.write(f"开始时间: {result.start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"结束时间: {end_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"总耗时: {(end_time - result.start_time).total_seconds():.1f} 秒\n")
        f.write(f"连接超时: {conn_timeout} 秒 | 命令超时: {cmd_timeout} 秒 | 上传超时: {upload_timeout} 秒\n\n") 


        command_parts = ["sshexec"]

        if args.mode == 'cmd':
            command_parts.append(f"-c \"{args.c}\"")
        else:
            command_parts.append(f"-s \"{os.path.abspath(args.s)}\"")
        command_parts.append(f"-f \"{os.path.abspath(args.f)}\"")

        if args.m != 'direct':
            command_parts.append(f"-m {args.m}")
        if args.n != 0:  
            command_parts.append(f"-n {args.n}")
        if args.t != f"{DEFAULT_CONN_TIMEOUT}-{DEFAULT_CMD_TIMEOUT}":
            command_parts.append(f"-t {args.t}")
        if args.p:
            command_parts.append(f"-p {args.p}")
        if args.d != 'y':
            command_parts.append(f"-d {args.d}")
        if args.disinteractive:
            command_parts.append("--disinteractive")

        command_line = ' '.join(command_parts)
        f.write("【执行命令】\n")
        f.write(f"  {command_line}\n\n")

        f.write("【执行参数】\n")
        f.write(f"  执行模式: {'命令模式' if args.mode == 'cmd' else '脚本模式'}\n")
        if args.mode == 'cmd':
            f.write(f"  执行命令: {args.c}\n")
        else:
            f.write(f"  执行脚本: {os.path.abspath(args.s)}\n")
        f.write(f"  执行权限: {'普通执行' if args.m == 'direct' else 'sudo权限'}\n")
        if args.n != 0:  
            f.write(f"  最大线程数: {args.n} 个\n")
        if args.p:
            f.write(f"  上传文件包: {args.p} (路径: {os.path.join(os.getcwd(), 'packages', args.p)})\n")
            f.write(f"  删除上传文件: {'是' if args.d == 'y' else '否'}\n")
        f.write(f"  节点文件: {os.path.abspath(args.f)}\n")
        f.write(f"  日志目录: {os.path.abspath(log_base)}\n\n")


        calculated_total = success_count + failure_count
        status_text = "核算校对一致" if calculated_total == total else "核算出现错误，请检查日志"
        
        f.write("【结果统计】\n")
        f.write(f"  全部：{total} | 成功：{success_count} | 失败：{failure_count}\n")
        f.write(f"  统计核算：{success_count}+{failure_count}={calculated_total} → 节点数 {total} → {status_text}\n") 

        if failure_count > 0:
            failure_counts = defaultdict(int)
            for err_type, ips in failure_details.items():
                if ips:
                    failure_counts[err_type] += len(ips)
            sorted_failures = sorted(failure_counts.items(), key=lambda x: x[1]) 
            
            failure_items = [f"{k}: {v}" for k, v in sorted_failures]

            f.write(f"  失败分类：{'  '.join(failure_items)}\n\n") 
        else:
            f.write("\n")


        f.write("\n【IP清单统计】\n")
        for err_type, ips in sorted(failure_details.items(), key=lambda item: (len(item[1]), item[0])): 
            if ips:
                f.write(f"\n{err_type} ({len(ips)}个):\n")
                for ip in sorted(ips, key=lambda ip: tuple(map(int, ip.split('.')))):
                    f.write(f"{ip}\n")
        
        if success_ips:
            f.write(f"\n成功节点 ({success_count}个):\n")
            for ip in sorted(success_ips, key=lambda ip: tuple(map(int, ip.split('.')))):
                f.write(f"{ip}\n")


    calculated_total = success_count + failure_count
    status_color = "\033[92m" if calculated_total == total else "\033[91m"
    status_text = "核算校对一致" if calculated_total == total else "核算出现错误，请检查日志"
    
    print(f"\n全部：{total} | {COLOR_GREEN}成功：{success_count}{COLOR_RESET} | {COLOR_RED}失败：{failure_count}{COLOR_RESET}")
    print(f"统计核算：{success_count}+{failure_count}={calculated_total} → 节点数 {total} → {status_color}{status_text}{COLOR_RESET}")


    if failure_count > 0:
        failure_items = [f"{COLOR_CYAN}{k}{COLOR_RESET}:{COLOR_YELLOW}{v}{COLOR_RESET}" for k, v in sorted_failures]
        print(f"失败分类：{'  '.join(failure_items)}")

def classify_error(ssh_result):
    if ssh_result.success:
        return '成功'

    error_type_map = {
        'password_expired': '密码过期',
        'authentication_failed': '密码错误',
        'port_unreachable': '端口不可达',
        'connection_timeout': '连接超时',
        'command_timeout': '执行超时',
        'upload_timeout': '上传超时',
        'ssh_error': 'SSH错误',
        'disk_full': '磁盘空间不足',
        'ssh_protocol_error': 'SSH协议错误',
        'transfer_error': '文件传输失败',
        'cleanup_failed': '清理失败',
        'other_errors': '其他错误'
    }
    
    error_type = getattr(ssh_result, 'error_type', None)
    if error_type in error_type_map:
        return error_type_map[error_type]

    exit_code = ssh_result.command_exec.get('exit_code', 0) if hasattr(ssh_result, 'command_exec') else 0
    if exit_code != 0:
        return f"退出码({exit_code})"

    password_expired = ssh_result.command_exec.get('password_expired', False) if hasattr(ssh_result, 'command_exec') else False
    if password_expired:
        return '密码过期'

    error_output = '\n'.join(ssh_result.error_lines).lower() if hasattr(ssh_result, 'error_lines') else ''
    if any(kw in error_output for kw in ['password expired', '密码过期']):
        return '密码过期'

    return '其他错误'


def process_node(node, config, log_base, result, command, package, script_path):
    try:
        ip, port, user, pwd = node
        conn_timeout, cmd_timeout, upload_timeout = get_timeout_values(f"{config.conn_timeout}-{config.cmd_timeout}-{config.upload_timeout}")  

        ssh_result = execute_ssh(
            ip=ip, port=port, user=user, pwd=pwd,
            config=config,
            command=config.command, 
            conn_timeout=conn_timeout, 
            cmd_timeout=cmd_timeout,
            upload_timeout=upload_timeout, 
            mode=config.mode, 
            script_path=config.script_path,
            sudo_mode=config.sudo_mode, 
            package=config.package,
            delete=config.delete, 
            log_base=config.log_base
        )

        log_generator = NodeLogGenerator(
            ip=ip, 
            ssh_result=ssh_result, 
            command=config.command, 
            package=config.package,
            script_path=config.script_path  
        )
        
        formatted_logs = log_generator.generate_formatted_logs()

        if not formatted_logs.strip():
            formatted_logs = f"【{ip}】[日志生成警告] 未捕获到具体错误信息，但节点处理失败"

        category = classify_error(ssh_result)
        log_dir = os.path.join(config.log_base, 'nodelogs', category)
        os.makedirs(log_dir, exist_ok=True)
        
        if config.package and ssh_result.upload_success and not ssh_result.directory_status:
            ssh_result.directory_status = {
                'path': ssh_result.sanitized_path,
                'exists': True
            }
            
        with open(os.path.join(log_dir, f"{ip}.log"), 'w', encoding='utf-8') as f:
            f.write(formatted_logs)


        sys.stdout.flush()

        print(formatted_logs)
        sys.stdout.flush()

        return ssh_result.success, ip, category
    
    except KeyboardInterrupt:
        raise 
    except Exception as e:
        if not hasattr(ssh_result, 'error_type'):
            ssh_result.error_type = 'other_errors'
        ssh_result.status = f"节点处理异常: {str(e)}"
        
    finally:
        log_generator = NodeLogGenerator(ip=ip, ssh_result=ssh_result, command=command, package=package, script_path=script_path)
        formatted_logs = log_generator.generate_formatted_logs()
        category = classify_error(ssh_result)
        log_dir = os.path.join(config.log_base, 'nodelogs', category)
        os.makedirs(log_dir, exist_ok=True)
        log_path = os.path.join(log_dir, f"{ip}.log")
        with open(log_path, 'w', encoding='utf-8') as f:
            f.write(formatted_logs)
        return category == '成功', ip, category
    

def validate_args(args, parser, nodes):

    if not hasattr(args, 'f') or not os.path.exists(args.f):
        parser.error("错误: 缺少必要的参数 -f，或指定的 CSV 文件不存在")

    if bool(args.c) == bool(args.s):
        parser.error("错误: 必须且只能指定一种执行模式（-c 或 -s）")

    if args.s:
        args.mode = 's'
        if not os.path.exists(args.s):
            parser.error(f"错误: 脚本文件 {args.s} 不存在")
        if not args.s.endswith(('.sh', '.py')):
            parser.error(f"错误: 脚本文件 {args.s} 必须是 .sh 或 .py 类型")

        try:
            validate_script_security(args.s)
        except SecurityCheckError as e:

            print_security_warnings(e, mode='script')
            if args.disinteractive:
                print(f"\033[93m非交互模式直接继续执行！\033[0m")
            else:
                try:
                    choice = input("\033[93m确认继续执行？(y/n) \033[0m").lower()
                except KeyboardInterrupt:
                    print(f"\n\033[93m操作已被用户取消\033[0m")
                    sys.exit(0)
                if choice != 'y':
                    print(f"\033[93m操作已被用户取消\033[0m")
                    sys.exit(0)
                print(f"\033[93m注意：您选择忽略安全检查继续执行！\033[0m\n")

        if os.path.getsize(args.s) == 0:
            parser.error("错误: 脚本文件为空")
        with open(args.s, 'rb') as f:
            content = f.read()
            if b'\r\n' in content:
                parser.error("错误：脚本使用了 Windows 换行符（CRLF），请转换为 Linux 换行符（LF）后再运行。")
            elif b'\r' in content and b'\n' not in content:
                parser.error("错误：脚本使用了 macOS 换行符（CR），请转换为 Linux 换行符（LF）后再运行。")

    if args.c:
        args.mode = 'cmd'
        if not args.c.strip():
            parser.error("错误: -c 参数不能为空")
        try:
            validate_command_security(args.c)
        except SecurityCheckError as e:

            print_security_warnings(e, mode='command')
            if args.disinteractive:
                print(f"\033[93m非交互模式直接继续执行！\033[0m")
            else:
                try:
                    choice = input("\033[93m确认继续执行？(y/n) \033[0m").lower()
                except KeyboardInterrupt:
                    print(f"\n\033[93m操作已被用户取消\033[0m")
                    sys.exit(0)
                if choice != 'y':
                    print(f"\033[93m操作已被用户取消\033[0m")
                    sys.exit(0)
                print(f"\033[93m注意：您选择忽略安全检查继续执行！\033[0m\n")

    if args.p:
        local_package_path = os.path.join(os.getcwd(), 'packages', args.p)
        if not os.path.exists(local_package_path):
            parser.error(f"错误: 上传包路径 {local_package_path} 不存在")
        if not any(os.listdir(local_package_path)):
            parser.error("错误: 上传包文件夹为空")

    if args.n < 0 or args.n > 10000:
        parser.error("错误: 线程数必须为 0 - 10000 之间的整数")
    args.n = min(args.n, len(nodes)) or len(nodes)
    args.n = max(1, args.n)

    if hasattr(args, 'd') and args.d:
        args.d = args.d.lower()
        if args.d not in ('y', 'n', 'yes', 'no'):
            parser.error("错误: -d 参数必须为 y/n")
        args.d = 'y' if args.d.startswith('y') else 'n'

    if args.m == 'direct' and args.p:
        if platform.system() == 'Linux':
            local_package_path = os.path.join(os.getcwd(), 'packages', args.p)
            has_root_file = False
            for root, _, files in os.walk(local_package_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    if os.stat(file_path).st_uid == 0:
                        has_root_file = True
                        break
                if has_root_file:
                    break
            if has_root_file:
                print(COLOR_RED + "\n 安全警告：检测到上传包中含有ROOT权限文件！\n"
                    "上传后无法自动删除，存在临时数据残留风险！" + COLOR_RESET)
                print("请检查以下文件：")
                for root, _, files in os.walk(local_package_path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        if os.stat(file_path).st_uid == 0:
                            print(f"  {file_path}")
                sys.exit(1)

    return args

def check_for_dangerous_patterns(content):
    issues = []
    lines = content.split('\n')
    for line_num, line_content in enumerate(lines, 1):

        stripped_line = line_content.strip()
        if stripped_line.startswith('#'):
            continue  
        
        for pattern in DANGEROUS_PATTERNS:
            if re.search(pattern['regex'], stripped_line, re.IGNORECASE):
                issues.append({
                    'line': line_num,
                    'content': stripped_line,
                    'pattern_name': pattern['name'],
                    'pattern_regex': pattern['regex']
                })
    if issues:
        raise SecurityCheckError(issues)

def validate_command_security(command):
    commands = re.split(r'[;\n]', command)
    content = '\n'.join([cmd.strip() for cmd in commands if cmd.strip()])
    check_for_dangerous_patterns(content)

def validate_script_security(script_path):
    if not os.path.exists(script_path):
        raise ValueError(f"脚本文件不存在: {script_path}")
    
    with open(script_path, 'rb') as f:
        content_bytes = f.read()
    
    checks = [
        (lambda: len(content_bytes) > 4096, "脚本体积超过4KB限制"),
        (lambda: re.search(rb'\r\n|\r(?!\n)', content_bytes), "必须使用LF换行符(Unix格式)"),
    ]
    
    for condition, error_msg in checks:
        if condition():
            raise ValueError(error_msg)
    
    try:
        content = content_bytes.decode('utf-8-sig')
    except UnicodeDecodeError:
        raise ValueError("脚本必须使用UTF-8编码（支持带BOM）")
    
    check_for_dangerous_patterns(content)    

def show_config(args, node_count):

    print("\n" + "=" * 40)
    print(f" {TOOL_NAME} 执行配置确认 ")
    print("=" * 40)
    print(f"目标节点数: {COLOR_GREEN}{node_count}{COLOR_RESET} 最大线程数: {COLOR_GREEN}{args.n if args.n > 0 else node_count}{COLOR_RESET}")
    print(f"节点清单：{COLOR_RED}{os.path.basename(args.f)}{COLOR_RESET}")
    print()

    if args.mode == 'cmd':
        print(f"执行模式: {COLOR_GREEN}命令模式（-c）{COLOR_RESET}")
        print(f"执行命令: {COLOR_RED}{args.c}{COLOR_RESET}")
    elif args.mode == 's':
        print(f"执行模式: {COLOR_GREEN}脚本模式（-s）{COLOR_RESET}")

        print(f"执行脚本: {COLOR_RED}{os.path.basename(args.s)}{COLOR_RESET}")


    print(f"执行权限: {COLOR_CYAN}{'正确权限' if args.m == 'direct' else 'sudo权限'}{COLOR_RESET}")
    
    conn_timeout, cmd_timeout, upload_timeout = get_timeout_values(args.t)  
    print(f"\n连接超时: {COLOR_YELLOW}{conn_timeout}{COLOR_RESET} 秒 | "
          f"命令超时: {COLOR_YELLOW}{cmd_timeout}{COLOR_RESET} 秒 | "
          f"上传超时: {COLOR_YELLOW}{upload_timeout}{COLOR_RESET} 秒")  
 

    if args.p:
        print()
        print(f"{COLOR_YELLOW}上传文件包结构：{COLOR_RESET}")
        print("=" * 40)
        local_package_path = os.path.join(os.getcwd(), 'packages', args.p)
        for root, dirs, files in os.walk(local_package_path):
            level = root[len(local_package_path):].count(os.sep)
            indent = '│   ' * level
            print(f"{indent}├─{os.path.basename(root)}/")
            sub_indent = '│   ' * (level + 1)
            for f in files:
                print(f"{sub_indent}├─ {f}")

    print("=" * 40)



def print_security_warnings(e, mode='script'):
    
    mode_name = '脚本' if mode == 'script' else '命令'
    print(f"\n\n{COLOR_YELLOW}⚠  安全警告：{mode_name}安全检查未通过，检测到以下潜在危险命令 ⚠{COLOR_RESET}\n")
    
    
    for idx, issue in enumerate(e.issues, 1):
        print(f"{COLOR_CYAN}[发现危险命令 {idx}]{COLOR_RESET}")
        print(f"{COLOR_YELLOW}├── 行号: {COLOR_RED}{issue['line']}{COLOR_RESET}")
        print(f"{COLOR_YELLOW}├── 类型: {COLOR_RED}{issue['pattern_name']}{COLOR_RESET}")
        print(f"{COLOR_YELLOW}├── 规则: {COLOR_RED}{issue['pattern_regex']}{COLOR_RESET}")
        print(f"{COLOR_YELLOW}└── 内容: {COLOR_RED}{issue['content']}{COLOR_RESET}\n")
    
    print(f"{COLOR_RED}⚠ 注意：上述操作可能导致以下后果：")
    print("   - 系统文件永久删除或损坏")
    print("   - 磁盘数据不可恢复性擦除")
    print("   - 系统权限配置异常")
    print(f"   - 关键服务不可用{COLOR_RESET}")


def package_latest_history():
    history_dir = 'historys'
    if not os.path.isdir(history_dir):
        print("错误: 历史记录目录 (historys) 不存在")
        return


    log_dirs = [d for d in os.listdir(history_dir) if os.path.isdir(os.path.join(history_dir, d))]
    
    if not log_dirs:
        print("错误: 历史记录目录中没有日志文件夹")
        return
    log_dirs.sort(reverse=True, key=lambda x: x.replace('_', ''))  
    latest_log_dir = log_dirs[0]


    current_dir = os.getcwd()
    package_name = f"log-{latest_log_dir}"
    zip_path = os.path.join(current_dir, f"{package_name}.zip")
    tar_path = os.path.join(current_dir, f"{package_name}.tar")


    zip_pattern = re.compile(r'log-\d{8}_\d{6}\.zip') 
    existing_zip_files = [f for f in os.listdir(current_dir) if zip_pattern.match(f)]
    for f in existing_zip_files:
        file_path = os.path.join(current_dir, f)
        os.remove(file_path)
        print(f"提示: 已删除旧打包文件 {f}")

    success = False
    if not success:
        try:
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_STORED) as zipf:
                source_dir = os.path.join(history_dir, latest_log_dir)
                for root, _, files in os.walk(source_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, source_dir)
                        zipf.write(file_path, arcname)
            print(f"打包成功: {os.path.basename(zip_path)}")
            success = True
        except Exception as e:
            print(f"ZIP打包失败: {str(e)}，尝试TAR打包")


    if not success:
        try:
            source_dir = os.path.join(history_dir, latest_log_dir)
            with tarfile.open(tar_path, "w") as tar:
                tar.add(source_dir, arcname=os.path.basename(source_dir))
            print(f"打包成功: {os.path.basename(tar_path)}")
            success = True
        except Exception as e:
            print(f"TAR打包失败: {str(e)}")

    if not success:
        print("错误: 未找到可用的打包工具 (zipfile/tarfile)")
        
def save_resources(log_base, args):

    resources_path = os.path.join(log_base, 'resources')
    os.makedirs(resources_path, exist_ok=True)
    

    shutil.copy(args.f, os.path.join(resources_path, os.path.basename(args.f)))
    

    if args.s:
        script_filename = os.path.basename(args.s)
        shutil.copy(args.s, os.path.join(resources_path, script_filename))
    

    if args.p:
        package_dir = os.path.join('packages', args.p)
        dest_package_dir = os.path.join(resources_path, args.p)
        if os.path.exists(dest_package_dir):
            shutil.rmtree(dest_package_dir)
        shutil.copytree(package_dir, dest_package_dir)

def get_timeout_values(timeout_str):
    try:
        timeout_parts = timeout_str.split('-')
        if len(timeout_parts) == 1:
            conn_timeout = int(timeout_parts[0])
            cmd_timeout = DEFAULT_CMD_TIMEOUT
            upload_timeout = DEFAULT_UPLOAD_TIMEOUT
        elif len(timeout_parts) == 2:
            conn_timeout = int(timeout_parts[0])
            cmd_timeout = int(timeout_parts[1])
            upload_timeout = DEFAULT_UPLOAD_TIMEOUT
        elif len(timeout_parts) >= 3:
            conn_timeout = int(timeout_parts[0])
            cmd_timeout = int(timeout_parts[1])
            upload_timeout = int(timeout_parts[2])
        else:
            raise ValueError("超时格式错误")
    except (ValueError, IndexError):
        conn_timeout = DEFAULT_CONN_TIMEOUT
        cmd_timeout = DEFAULT_CMD_TIMEOUT
        upload_timeout = DEFAULT_UPLOAD_TIMEOUT
    return conn_timeout, cmd_timeout, upload_timeout 




def main():
    check_dependencies()
    shutdown_event.clear()

    def graceful_shutdown(signum, frame):
        print(f"\n{COLOR_RED}接收到终止信号，正在终止...{COLOR_RESET}")
        shutdown_event.set()
        with ssh_connection_lock:
            for client in active_ssh_clients[:]:
                try:
                    transport = client.get_transport()
                    if transport and transport.is_active():
                        transport.close()
                except Exception as e:
                    pass
                active_ssh_clients.remove(client)
        
        sys.stdout.flush()
        sys.stderr.flush()

        os._exit(1)  

    signal.signal(signal.SIGINT, graceful_shutdown)
    signal.signal(signal.SIGTERM, graceful_shutdown)


    try:
        if DEFAULT_SUDO_MODE not in ("direct", "sudo"):
            print(f"{COLOR_RED}错误：DEFAULT_SUDO_MODE 配置错误，必须为 'direct' 或 'sudo'，当前值为：{DEFAULT_SUDO_MODE}{COLOR_RESET}")
            sys.exit(1)

        if DEFAULT_DELETE not in ("y", "n"):
            print(f"{COLOR_RED}错误：DEFAULT_DELETE 配置错误，必须为 'y' 或 'n'，当前值为：{DEFAULT_DELETE}{COLOR_RESET}")
            sys.exit(1)
        parser, args = parse_args()
        if args.z:
            other_args = [arg for arg in sys.argv[1:] if arg != '-z' and not arg.startswith('-z')]
            if len(other_args) > 0:
                print("提示: -z 是独立的功能参数，不与其他参数一起使用。")
                sys.exit(1)
            package_latest_history()
            sys.exit(0)

        if args.g:
            try:
                from core.sshexec_get import Downloader
                
                nodes = read_nodes(args.f)
                if not nodes:
                    sys.exit(1)
                    
                downloader = Downloader(
                    remote_path=args.g,
                    local_dir=args.l,
                    nodes=nodes,
                    conn_timeout=DEFAULT_CONN_TIMEOUT,
                    download_timeout= DOWNLOAD_TIMEOUT
                )
                
                max_workers = DEFAULT_CONCURRENT
                download_timeout = DOWNLOAD_TIMEOUT

                if args.n > 0:
                    max_workers = min(args.n, len(nodes))
                else:
                    max_workers = min(DEFAULT_CONCURRENT, len(nodes))
                
                max_workers = max(1, max_workers)

                downloader.download_all(max_workers=max_workers)
                
                sys.exit(0)

            except Exception as e:
                print(f"{COLOR_RED}下载功能出错: {str(e)}{COLOR_RESET}")
                traceback.print_exc()
                sys.exit(1)


        if not args.f or (not args.c and not args.s):
            parser.error("错误: 必须提供 -f 和 (-c 或 -s) 参数")

        nodes = read_nodes(args.f)
        if not nodes:
            print(f"{COLOR_RED}错误：CSV文件中无有效节点{COLOR_RESET}")
            sys.exit(1)

        if args.disinteractive:
            empty_passwords = [node for node in nodes if not node[3]]
            if empty_passwords:
                print("错误: --disinteractive模式下节点的密码不能为空")
                sys.exit(1)

        args = validate_args(args, parser, nodes)
        conn_timeout, cmd_timeout, upload_timeout = get_timeout_values(args.t)  


        result = ExecutionResult()
        result.command = args.c if args.mode == 'cmd' else args.s
        result.mode = args.mode
        result.sudo_mode = args.m
        result.p = args.p
        result.d = args.d
        result.command_line = ' '.join(sys.argv)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_base = os.path.join('historys', timestamp)
        os.makedirs(os.path.join(log_base, 'nodelogs'), exist_ok=True)

        
        if not args.disinteractive:
            show_config(args, len(nodes))
            try:
                user_input = input("\n是否确认执行？(y/n) ").lower()
                if user_input != 'y':
                    print("操作已被用户取消")
                    sys.exit(0)
            except KeyboardInterrupt:
                print("\n操作已被用户取消。")
                sys.exit(0)

        global_start_time = datetime.now()
        result = ExecutionResult()
        result.start_time = global_start_time 
        if not args.disinteractive and any(node[3] == '' for node in nodes):
            common_pwd = getpass.getpass("检测到CSV文件中存在空密码的节点，请输入统一的SSH认证密码：")
            nodes = [
                (ip, port, user, common_pwd if pwd == '' else pwd)
                for ip, port, user, pwd in nodes
            ]

        config = Config(
            command=args.c if args.mode == 'cmd' else '', 
            conn_timeout=conn_timeout,
            cmd_timeout=cmd_timeout,
            upload_timeout=upload_timeout,  
            mode=args.mode,
            script_path=args.s.replace("\\", "/") if args.s else None,
            sudo_mode=args.m,
            package=args.p,
            delete=args.d,
            log_base=log_base
        )
        if args.p:
            if shutil.which('rsync'):
                print(f"检测到rsync工具，将使用{COLOR_GREEN}rsync{COLOR_RESET}进行高效文件上传")
                config.upload_method = 'rsync'
            else:
                print(f"未检测到rsync工具，将使用{COLOR_YELLOW}sftp{COLOR_RESET}进行文件上传")
                config.upload_method = 'sftp'
        else:
            config.upload_method = None
            
        max_workers = args.n if args.n > 0 else len(nodes)
        max_workers = min(max_workers, len(nodes))
        result.start_time = global_start_time

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {}
            try:
                for node in nodes:
                    if shutdown_event.is_set(): 
                        break
                    future = executor.submit(
                        process_node, node, config, log_base, 
                        result, config.command,
                        config.package, config.script_path
                    )
                    futures[future] = node
                    future.add_done_callback(lambda f: shutdown_event.is_set() and f.cancel())

                for future in as_completed(futures):
                    if shutdown_event.is_set():
                        executor.shutdown(wait=False)
                        break
                    node = futures[future]
                    try:
                        success, ip, category = future.result()
                    except Exception as e:
                        error_msg = f"future.result()异常: {str(e)}\n{traceback.format_exc()}"
                        result.add_failure('other_errors', node[0], error_msg)
                        result_log = SSHResult()
                        result_log.error_type = 'other_errors'
                        result_log.status = error_msg
                        log_generator = NodeLogGenerator(
                            ip=node[0], 
                            ssh_result=result_log, 
                            command=config.command, 
                            package=config.package,
                            script_path=config.script_path
                        )
                        fallback_log = log_generator.generate_formatted_logs()
                        fallback_log_dir = os.path.join(log_base, 'nodelogs', '其他错误')
                        os.makedirs(fallback_log_dir, exist_ok=True)
                        with open(os.path.join(fallback_log_dir, f"{node[0]}.log"), 'w', encoding='utf-8') as f:
                            f.write(fallback_log)
            except KeyboardInterrupt:
                print(f"\n{COLOR_RED}正在强制终止所有线程...{COLOR_RESET}")
                executor.shutdown(wait=False)  
                for future in futures:
                    future.cancel()  
                raise  
        save_results(log_base, result, len(nodes), conn_timeout, cmd_timeout, upload_timeout, args)  
        global_end_time = datetime.now()
        total_duration = global_end_time - global_start_time
        print(f"\n开始时间: {global_start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"结束时间: {global_end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"总耗时: {total_duration.total_seconds():.1f} 秒")
        try:
            rename_nodelog_folders(log_base)
            merge_nodelogs_to_combined(log_base)
            convert_combined_log_to_xlsx(log_base)
            nodelogs_dir = os.path.join(log_base, 'nodelogs')
            if os.path.exists(nodelogs_dir):
                try:
                    shutil.rmtree(nodelogs_dir)
                except Exception as e:
                    print(f"[ERROR] 清理临时日志失败: {nodelogs_dir} - {str(e)}")
        except Exception as e:
            print(f"{COLOR_RED}生成报告文件时出现错误：{str(e)}{COLOR_RESET}")
        nodelogs_dir = os.path.join(log_base, 'nodelogs')
        if os.path.exists(nodelogs_dir):
            try:
                tar_path = os.path.join(log_base, 'nodelogs.tar.gz')
                with tarfile.open(tar_path, 'w:gz') as tar:
                    tar.add(nodelogs_dir, arcname=os.path.basename(nodelogs_dir))
            except Exception as e:
                print(f"{COLOR_YELLOW}警告：日志打包失败 - {str(e)}{COLOR_RESET}")
            try:
                shutil.rmtree(nodelogs_dir)
            except Exception as e:
                print(f"{COLOR_RED}错误：无法删除日志目录 - {str(e)}{COLOR_RESET}")
        if platform.system() == 'Linux':
            create_latest_log_symlink()
        save_resources(log_base, args)
    except SystemExit: pass
    except Exception as e:
        error_msg = f"全局错误: {str(e)}\n{traceback.format_exc()}"
        print(f"\n{COLOR_RED}发生未预期的错误{COLOR_RESET}")
    finally:
        with ssh_connection_lock:
            for client in active_ssh_clients[:]:
                try:
                    transport = client.get_transport()
                    if transport and transport.is_active():
                        transport.close()
                except Exception as e:
                    pass
                active_ssh_clients.remove(client)
        if 'executor' in locals():
            executor.shutdown(wait=False)

if __name__ == "__main__":
    main()