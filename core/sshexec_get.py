# -*- coding: utf-8 -*-

import os
import sys
import stat
import paramiko
import socket
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from core.sshexec_config import (
    COLOR_GREEN, COLOR_RED, COLOR_CYAN, 
    COLOR_YELLOW, COLOR_RESET,
    DEFAULT_CONN_TIMEOUT,
    DOWNLOAD_TIMEOUT
)
from core.sshexec_utils import read_nodes

class DownloadResult:
    def __init__(self):
        self.start_time = datetime.now()
        self.end_time = None
        self.duration = None
        self.success = False
        self.error_type = None
        self.status = ""
        self.files_downloaded = []
        self.files_failed = []
        self.dirs_created = []
        self.download_timeout = DOWNLOAD_TIMEOUT

class Downloader:
    def __init__(self, remote_path, local_dir, nodes, conn_timeout=DEFAULT_CONN_TIMEOUT, download_timeout=DOWNLOAD_TIMEOUT):
        self.remote_path = remote_path
        self.local_dir = local_dir
        self.nodes = nodes
        self.conn_timeout = conn_timeout
        self.download_timeout = DOWNLOAD_TIMEOUT
        self.shutdown_event = threading.Event()
        self.active_clients = []
        self.client_lock = threading.Lock()
        self.use_rsync = self.check_rsync_available() 

    def is_windows(self):
        return sys.platform.startswith('win')
    
    def graceful_shutdown(self, signum, frame):
        print(f"\n{COLOR_RED}接收到终止信号，正在终止下载...{COLOR_RESET}")
        self.shutdown_event.set()
        with self.client_lock:
            for client in self.active_clients[:]:
                try:
                    transport = client.get_transport()
                    if transport and transport.is_active():
                        transport.close()
                except Exception:
                    pass
                self.active_clients.remove(client)
        sys.exit(1)

    def connect_ssh(self, ip, port, user, pwd):
        if self.shutdown_event.is_set():
            return None, "用户终止操作"

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            if self.is_windows():
                client.connect(
                    ip, int(port),
                    username=user, password=pwd,
                    timeout=self.conn_timeout,
                    banner_timeout=self.conn_timeout,
                    allow_agent=False,
                    look_for_keys=False
                )
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.conn_timeout)
                sock.connect((ip, int(port)))
                
                client.connect(
                    ip, int(port),
                    username=user, password=pwd,
                    timeout=self.conn_timeout,
                    banner_timeout=self.conn_timeout,
                    sock=sock
                )
            
            with self.client_lock:
                self.active_clients.append(client)
            return client, None
        except (socket.timeout, socket.error) as e:
            error_msg = f"连接错误: {str(e)}"
            if hasattr(e, 'winerror') and e.winerror == 10038:
                error_msg = "Windows套接字错误 (10038)"
            return None, error_msg
        except paramiko.AuthenticationException:
            return None, "用户名/密码错误"
        except paramiko.SSHException as e:
            return None, f"SSH协议错误: {str(e)}"
        except Exception as e:
            return None, f"连接错误: {str(e)}"

    def check_rsync_available(self):
        import subprocess
        try:
            subprocess.run(["rsync", "--version"], check=True, 
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except (FileNotFoundError, subprocess.CalledProcessError):
            return False

    def download_with_rsync(self, remote_path, local_path, ip):
        import subprocess
        try:
            cmd = [
                "rsync", "-avz", 
                f"{self.user}@{ip}:{remote_path}", 
                local_path
            ]
            subprocess.run(cmd, check=True, timeout=self.download_timeout)
            return True, None
        except Exception as e:
            return False, f"rsync下载失败: {str(e)}"
        
    def download_file(self, sftp, remote_path, local_path, ip):

        if self.use_rsync:
            return self.download_with_rsync(remote_path, local_path, ip)
        else:
            try:
                remote_attr = sftp.stat(remote_path)
                if remote_attr.st_uid == 0 and remote_attr.st_mode & 0o77 != 0:
                    self.log(f"警告: {ip} 下载root文件 {remote_path} (权限:{oct(remote_attr.st_mode)})")
                
                if not os.path.exists(os.path.dirname(local_path)):
                    os.makedirs(os.path.dirname(local_path), exist_ok=True)
                    
                sftp.get(remote_path, local_path)
                return True, None
            except Exception as e:
                return False, f"文件下载失败: {str(e)}"

    def download_directory(self, sftp, remote_path, local_base, ip, result):
        try:
            remote_items = sftp.listdir_attr(remote_path)
            
            local_dir = os.path.join(local_base, os.path.basename(remote_path) + f"_{ip}")
            if not os.path.exists(local_dir):
                os.makedirs(local_dir, exist_ok=True)
                result.dirs_created.append(local_dir)
            
            for item in remote_items:
                if self.shutdown_event.is_set():
                    return False, "用户终止操作"
                    
                remote_item = os.path.join(remote_path, item.filename).replace("\\", "/")
                local_item = os.path.join(local_dir, item.filename)
                
                if not item.filename.startswith('.'): 
                    if self.is_sftp_directory(sftp, remote_item):
                        self.download_directory(sftp, remote_item, local_dir, ip, result)
                    else:
                        file_ext = os.path.splitext(item.filename)[1]
                        file_name = os.path.splitext(item.filename)[0]
                        new_filename = f"{file_name}_{ip}{file_ext}"
                        new_local_path = os.path.join(local_dir, new_filename)
                        
                        sftp.get(remote_item, new_local_path)
                        result.files_downloaded.append({
                            'remote': remote_item,
                            'local': new_local_path,
                            'size': item.st_size
                        })
            return True, None
        except Exception as e:
            return False, f"目录下载失败: {str(e)}"

    def is_sftp_directory(self, sftp, path):
        try:
            return stat.S_ISDIR(sftp.stat(path).st_mode)
        except:
            return False

    def process_node(self, node):
        ip, port, user, pwd = node
        result = DownloadResult()
        
        if self.shutdown_event.is_set():
            result.error_type = "user_abort"
            result.status = "用户终止操作"
            return result, ip
            
        client, error = self.connect_ssh(ip, port, user, pwd)
        if not client:
            result.error_type = "connection_error"
            result.status = error
            return result, ip
            
        try:
            sftp = client.open_sftp()
            
            try:
                remote_stat = sftp.stat(self.remote_path)
                is_directory = stat.S_ISDIR(remote_stat.st_mode)
            except FileNotFoundError:
                result.error_type = "file_not_found"
                result.status = f"远程路径不存在: {self.remote_path}"
                return result, ip
                
            if is_directory:
                success, error = self.download_directory(
                    sftp, self.remote_path, self.local_dir, ip, result
                )
                if success:
                    result.success = True
                    result.status = f"目录下载成功: {self.remote_path}"
                else:
                    result.error_type = "download_error"
                    result.status = error
            else:
                file_ext = os.path.splitext(self.remote_path)[1]
                file_name = os.path.splitext(os.path.basename(self.remote_path))[0]
                new_filename = f"{file_name}_{ip}{file_ext}"
                local_path = os.path.join(self.local_dir, new_filename)
                
                success, error = self.download_file(
                    sftp, self.remote_path, local_path, ip
                )
                
                if success:
                    result.success = True
                    result.status = f"文件下载成功: {self.remote_path}"
                    result.files_downloaded.append({
                        'remote': self.remote_path,
                        'local': local_path,
                        'size': remote_stat.st_size
                    })
                else:
                    result.error_type = "download_error"
                    result.status = error
                    
        except Exception as e:
            if "timed out" in str(e).lower():
                result.error_type = "timeout"
                result.status = f"操作超时: {str(e)}"
            elif "authentication" in str(e).lower():
                result.error_type = "auth_error"
                result.status = "认证失败"
            elif "EOF" in str(e):
                result.error_type = "connection_reset"
                result.status = "连接意外终止"
            else:
                result.error_type = "unknown_error"
                result.status = f"未知错误: {str(e)}"
            traceback.print_exc()
        finally:
            result.end_time = datetime.now()
            result.duration = result.end_time - result.start_time
            try:
                sftp.close()
            except:
                pass
            try:
                client.close()
            except:
                pass
            with self.client_lock:
                if client in self.active_clients:
                    self.active_clients.remove(client)
                    
        return result, ip

    def download_all(self, max_workers=5):
        self.local_dir = os.path.abspath(self.local_dir)
        
        if not os.path.isabs(self.local_dir):
            abs_path = os.path.abspath(self.local_dir)
            print(f"{COLOR_YELLOW}转换为绝对路径: {abs_path}{COLOR_RESET}")
            self.local_dir = abs_path
        if not os.path.exists(self.local_dir):
            try:
                os.makedirs(self.local_dir, exist_ok=True)
                print(f"{COLOR_GREEN}已创建本地目录: {self.local_dir}{COLOR_RESET}")
            except Exception as e:
                print(f"{COLOR_RED}创建本地目录失败: {str(e)}{COLOR_RESET}")
                return
        self.local_dir = os.path.normpath(self.local_dir).replace("\\", "/")   
        try:
            test_file = os.path.join(self.local_dir, "write_test.tmp")
            with open(test_file, 'w') as f:
                f.write("test")
            os.remove(test_file)
        except Exception as e:
            print(f"{COLOR_RED}本地目录不可写: {self.local_dir} - {str(e)}{COLOR_RESET}")
            return
        
        print(f"\n{COLOR_CYAN}配置信息确认{COLOR_RESET}")
        print(f"远程路径: {COLOR_YELLOW}{self.remote_path}{COLOR_RESET}")
        print(f"本地目录: {COLOR_YELLOW}{self.local_dir}{COLOR_RESET}")
        print(f"节点数量: {COLOR_CYAN}{len(self.nodes)}{COLOR_RESET}")

        try:
            user_input = input("\n是否确认执行？(y/n) ").lower()
            if user_input != 'y':
                print("操作已被用户取消")
                sys.exit(0)
        except KeyboardInterrupt:
            print("\n操作已被用户取消。")
            sys.exit(0)
        
        results = []
        success_count = 0
        failure_count = 0
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self.process_node, node): node for node in self.nodes}
            
            for future in as_completed(futures):
                if self.shutdown_event.is_set():
                    executor.shutdown(wait=False)
                    break
                    
                node = futures[future]
                try:
                    result, ip = future.result()
                    results.append(result)
                    
                    if result.success:
                        success_count += 1
                        status_color = COLOR_GREEN
                    else:
                        failure_count += 1
                        status_color = COLOR_RED
                        
                    print(f"【{ip}】{status_color}{result.status}{COLOR_RESET}")
                    
                except Exception as e:
                    print(f"节点处理异常: {str(e)}")
                    traceback.print_exc()
        
        self.generate_report(results, success_count, failure_count)
        
    
        print(f"成功: {COLOR_GREEN}{success_count}{COLOR_RESET} | 失败: {COLOR_RED}{failure_count}{COLOR_RESET}")
        print(f"总耗时: {COLOR_CYAN}{(datetime.now() - results[0].start_time).total_seconds():.2f}{COLOR_RESET}秒\n")
        
    def generate_report(self, results, success_count, failure_count):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        history_dir = "historys"
        if not os.path.exists(history_dir):
            os.makedirs(history_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_dir = os.path.join(history_dir, f"download_report_{timestamp}")
        os.makedirs(report_dir, exist_ok=True)


        os.makedirs(report_dir, exist_ok=True)
        
        report_path = os.path.join(report_dir, "download_report.txt")
        
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(f"{'='*40} 下载报告 {'='*40}\n")
            f.write(f"远程路径: {self.remote_path}\n")
            f.write(f"本地目录: {self.local_dir}\n")

            if results:
                start_time = results[0].start_time.strftime('%Y-%m-%d %H:%M:%S')
            else:
                start_time = "无数据"
            
            f.write(f"开始时间: {results[0].start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"结束时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"节点总数: {len(results)}\n")
            f.write(f"成功: {success_count} | 失败: {failure_count}\n\n")
            
            f.write(f"{'='*40} 成功下载 {'='*40}\n")
            for result in results:
                if result.success:
                    f.write(f"节点: {result.files_downloaded[0]['local'].split('_')[-1]}\n")
                    f.write(f"状态: {result.status}\n")
                    
                    if hasattr(result, 'dirs_created') and result.dirs_created:
                        f.write(f"创建的目录: {result.dirs_created[0]}\n")
                    
                    for file_info in result.files_downloaded:
                        f.write(f"  - 远程: {file_info['remote']}\n")
                        f.write(f"    本地: {file_info['local']}\n")
                        f.write(f"    大小: {file_info['size']} 字节\n")
                    f.write("\n")
            
            f.write(f"{'='*40} 失败详情 {'='*40}\n")
            for result in results:
                if not result.success:
                    ip = "未知"
                    if result.files_downloaded:
                        ip = result.files_downloaded[0]['local'].split('_')[-1]
                    elif result.dirs_created:
                        ip = result.dirs_created[0].split('_')[-1]
                        
                    f.write(f"节点: {ip}\n")
                    f.write(f"错误类型: {result.error_type}\n")
                    f.write(f"错误信息: {result.status}\n")
                    f.write(f"耗时: {result.duration.total_seconds():.2f}秒\n\n")
                    if hasattr(result, 'traceback'):
                        f.write("\n错误追踪:\n")
                        f.write(result.traceback)
                        
                    f.write("\n")
            f.write(f"{'='*40} 统计信息 {'='*40}\n")
            f.write(f"总文件数: {sum(len(r.files_downloaded) for r in results)}\n")
            f.write(f"总目录数: {sum(len(r.dirs_created) for r in results if hasattr(r, 'dirs_created'))}\n")
        
        print(f"\n下载报告已保存至：{COLOR_GREEN}{report_path}{COLOR_RESET}")