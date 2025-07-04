# -*- coding: utf-8 -*-
import sys
import os
import re


def parse_args():
    import argparse
    from core.sshexec_config import (TOOL_NAME, VERSION, DEFAULT_SUDO_MODE, DEFAULT_TIMEOUT, DEFAULT_DELETE, DEFAULT_CONCURRENT)
    parser = argparse.ArgumentParser(
        description=f"\n{TOOL_NAME} v{VERSION} - SSH 批量执行和下载工具\n"
                    "模式说明:\n"
                    "  执行模式: 使用 -c 或 -s 参数\n"
                    "  下载模式: 使用 -g 参数\n"
                    "  日志打包: 使用 -z 参数\n"
                    "示例：\n"
                    "  执行命令: python sshexec.py -c \"ls -l\" -f nodes.csv\n"
                    "  执行脚本: python sshexec.py -s script.sh -f nodes.csv\n"
                    "  下载文件: python sshexec.py -g \"/path/to/remote\" -f nodes.csv -l ./downloads\n"
                    "  打包日志: python sshexec.py -z",
        formatter_class=argparse.RawTextHelpFormatter,
        usage=f"usage: {TOOL_NAME}.py [-h] (-c COMMAND | -s SCRIPT | -g REMOTE_PATH) -f FILE [可选参数]"
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-c', metavar='COMMAND', help='⚠ （必填）⚠ （命令模式）      后面填写要执行的命令')
    group.add_argument('-s', metavar='SCRIPT', help='⚠ （必填）⚠ （脚本模式）      后面填写执行的脚本路径')
    group.add_argument('-g', metavar='REMOTE_PATH', help='⚠ （可选）⚠ （下载模式）      下载远程文件/目录路径（必须用双引号包裹）')
    parser.add_argument('-f', metavar='FILE', help='⚠ （必填）⚠                   后面填写节点信息的 CSV 文件路径')
    parser.add_argument('-p', metavar='PACKAGE', help='  （选填）                    指定要上传的文件包名，对应当前路径下的 packages 目录下的子目录名称')
    parser.add_argument('-m', metavar='MODE', choices=['direct', 'sudo'], default=DEFAULT_SUDO_MODE, help=f'  （选填）  [默认值: {DEFAULT_SUDO_MODE}]    执行权限模式 ，direct 为普通执行，sudo 为以 sudo 权限执行')
    parser.add_argument('-n', metavar='THREADS', type=int, default=0, help=f'  （选填）  [默认值: 0]       设置最大工作线程数，0 表示最大线程数执行，需要填写大于等于0的整数。')

    parser.add_argument('-t', metavar='TIMEOUT', default=DEFAULT_TIMEOUT, help=f'  （选填）  [默认值: {DEFAULT_TIMEOUT}]   设置连接和执行超时时间（秒），格式：连接超时-命令超时 ')
    parser.add_argument('-d', metavar='DELETE', choices=['y', 'n'], default=DEFAULT_DELETE, help=f'  （选填）  [默认值: {DEFAULT_DELETE}]       需与 -p 一起使用，表示执行命令后是否删除上传的文件，y 为删除，n 为保留')
    parser.add_argument('-l', '--local-dir', dest='l', metavar='LOCAL_DIR', help='  （必填）（仅用于-g模式）  指定下载文件的本地存放目录')
    parser.add_argument('-z', action='store_true', help='  （独立功能，仅支持Linux）   打包最新日志，不可与其他参数一起使用，打包前会删除当前旧打包文件')
    parser.add_argument('--disinteractive', action='store_true', help='                              取消交互确认，直接执行命令')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    if args.s:
        args.s = args.s.replace("\\", "/")
    if args.f:
        args.f = args.f.replace("\\", "/")
    if args.g:
        if not args.f or not args.l:  
            parser.error("错误: -g 模式必须同时提供 -f 和 -l 参数")
        if args.c or args.s or args.p:
            parser.error("错误: -g 模式不能与 -c、-s 或 -p 参数同时使用")
        args.g = args.g.replace("\\", "/")
        args.l = args.l.replace("\\", "/")
    return parser, args

def read_nodes(csv_path):
    from core.sshexec_config import DEFAULT_IP_PORT, DEFAULT_USER, DEFAULT_PASSWORD
    import csv
    import base64
    
    if not csv_path.endswith('.csv'):
        print(f"错误: {csv_path} 不是 CSV 文件")
        sys.exit(1)
    
    default_pwd = ""
    if DEFAULT_PASSWORD:
        try:
            default_pwd = base64.b64decode(DEFAULT_PASSWORD.encode()).decode('utf-8')
        except Exception as e:
            print(f"错误: 默认密码BASE64解码失败 - {str(e)}")
            sys.exit(1)
    
    nodes = []
    ip_set = set()
    line_count = 0
    
    try:
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.reader(f, delimiter=',', skipinitialspace=True)
            
            for row_idx, row in enumerate(reader, 1):
                line_count += 1
                
                if not row or not any(field.strip() for field in row):
                    print(f"提示: 第{row_idx}行为空，已跳过")
                    continue
                    
                if len(row) == 1:
                    parts = [x.strip() for x in row[0].split(None, 1)]
                    if len(parts) > 1:
                        row = parts[:2] + [''] 
                    else:
                        row = [parts[0], '', ''] 
                elif len(row) < 3:
                    row += [''] * (3 - len(row))
                
                row = row[:4]
                
                try:
                    ip = row[0].strip()
                    if not ip:
                        print(f"错误: {csv_path} 第{row_idx}行 - IP地址为空")
                        sys.exit(1)
                        
                    if ip in ip_set:
                        print(f"错误: {csv_path} 第{row_idx}行 - IP地址 {ip} 重复")
                        sys.exit(1)
                    ip_set.add(ip)
                    
                    port_str = row[1].strip() if len(row) > 1 else ''
                    if not port_str:
                        if not DEFAULT_IP_PORT:
                            print(f"错误: {csv_path} 第{row_idx}行 - 端口为空且未配置默认端口")
                            print("提示: 请在配置文件中设置 DEFAULT_IP_PORT 或在CSV中指定端口")
                            sys.exit(1)
                        port_str = DEFAULT_IP_PORT
                    
                    if ':' in ip:
                        ip, port_str = ip.split(':', 1)
                        ip = ip.strip()
                        port_str = port_str.strip()
                        if not port_str:
                            print(f"错误: {csv_path} 第{row_idx}行 - 端口 '{port_str}' 不是数字")
                            sys.exit(1)
                    
                    try:
                        port = int(port_str)
                    except ValueError:
                        print(f"错误: {csv_path} 第{row_idx}行 - 端口 '{port_str}' 不是数字")
                        sys.exit(1)
                        
                    if not (1 <= port <= 65535):
                        print(f"错误: {csv_path} 第{row_idx}行 - 端口值 {port} 超出范围(1-65535)")
                        sys.exit(1)
                    
                    user = row[2].strip() if len(row) > 2 else ''
                    if not user:
                        if DEFAULT_USER:
                            user = DEFAULT_USER
                        else:
                            print(f"错误: {csv_path} 第{row_idx}行 - 用户名为空且未配置默认用户")
                            print("提示: 请在配置文件中设置 DEFAULT_USER 或在CSV中指定用户")
                            sys.exit(1)
                    
                    pwd = row[3].strip() if len(row) > 3 else ''
                    if not pwd:
                        pwd = default_pwd
                    
                    nodes.append((ip, port, user, pwd))
                    
                except ValueError as ve:
                    print(f"格式错误: {csv_path} 第{row_idx}行 - {str(ve)}")
                    sys.exit(1)
                except Exception as e:
                    print(f"处理错误: {csv_path} 第{row_idx}行 - {str(e)}")
                    sys.exit(1)
                    
        if line_count == 0:
            print(f"错误: {csv_path} 是空文件")
            sys.exit(1)
            
    except FileNotFoundError:
        print(f"错误: CSV文件不存在 - {csv_path}")
        sys.exit(1)
    except Exception as e:
        print(f"读取CSV失败: {str(e)}")
        sys.exit(1)
        
    if not nodes:
        print(f"错误: {csv_path} 中无有效节点")
        sys.exit(1)
        
    return nodes



def check_dependencies():
    import paramiko

    if not hasattr(paramiko, "SSHClient"):
        print("错误: paramiko 库功能缺失，可能因安装不完整导致")
        sys.exit(1)

    min_version = (3, 8)  
    if sys.version_info < min_version:
        print(f"错误: 请使用Python {min_version[0]}.{min_version[1]}+")
        sys.exit(1)

    required_versions = {
        'paramiko': '2.7.1'  
    }

    from importlib.metadata import version
    for package, min_version in required_versions.items():
        try:
            installed_version = version(package)
            if tuple(map(int, installed_version.split('.'))) < tuple(map(int, min_version.split('.'))):
                raise ValueError(f"{package} 版本过低 (需要 >= {min_version})")
        except Exception as e:
            print(f"依赖错误: {str(e)}")
            print("请执行以下命令升级：")
            print(f"pip install --upgrade {package}")
            sys.exit(1)

def create_latest_log_symlink():
    if os.path.isdir('historys'):
        all_log_dirs = [d for d in os.listdir('historys') if os.path.isdir(os.path.join('historys', d))]
        all_log_dirs.sort(reverse=True, key=lambda x: x[:8] + x[9:15])
        if all_log_dirs:
            latest_history_dir = os.path.join('historys', all_log_dirs[0])
            latest_link = os.path.join(os.getcwd(), 'latest_history')
            try:
                if os.path.exists(latest_link):
                    if os.path.islink(latest_link):
                        os.remove(latest_link)
                os.symlink(latest_history_dir, latest_link)

            except OSError as e:
                print(f"\n警告: 创建符号链接失败: {str(e)}")
                if e.errno == 1:
                    print("提示: 请尝试使用管理员/root权限运行")


def rename_nodelog_folders(log_base):
    import shutil

    nodelog_dir = os.path.join(log_base, 'nodelogs')
    if not os.path.exists(nodelog_dir):
        return

    for category in os.listdir(nodelog_dir):
        category_dir = os.path.join(nodelog_dir, category)
        if os.path.isdir(category_dir):
            log_files = [f for f in os.listdir(category_dir) if f.endswith('.log')]
            count = len(log_files)

            new_category_name = f"{category}-{count}"
            new_category_dir = os.path.join(nodelog_dir, new_category_name)

            if os.path.exists(new_category_dir):
                try:
                    shutil.rmtree(new_category_dir) 
                    print(f"[INFO] 已清理旧目录: {new_category_dir}")
                except Exception as e:
                    print(f"[ERROR] 清理旧目录失败: {new_category_dir} - {str(e)}")
                    continue  
            try:
                os.rename(category_dir, new_category_dir)
            except PermissionError as e:
                print(f"[ERROR] 权限不足，无法重命名目录: {category_dir} -> {new_category_dir}")
                print(f"[ERROR] 详情: {str(e)}")
            except Exception as e:
                print(f"[ERROR] 重命名目录失败: {str(e)}")

def convert_combined_log_to_xlsx(log_base):
    import openpyxl

    try: 
        combined_log_path = os.path.join(log_base, "combined.log")
        if not os.path.exists(combined_log_path):
            raise FileNotFoundError(f"合并日志文件 {combined_log_path} 不存在")
        if os.path.getsize(combined_log_path) == 0:
            raise ValueError("合并日志文件为空")

        xlsx_path = os.path.join(log_base, "combined.xlsx")
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "执行日志"
        
        ws.column_dimensions['A'].width = 16  
        ws.column_dimensions['B'].width = 70  
        ws.column_dimensions['C'].width = 100 
        
        header = ["IP地址", "日志内容", "输出详情"]
        ws.append(header)
        from openpyxl.styles import Font
        for cell in ws[1]:
            cell.font = Font(bold=True, color="FF0000")

        ws.freeze_panes = 'A2'  
        ws.auto_filter.ref = 'A1:C1' 

        log_pattern = re.compile(
            r'^【(?P<ip>\d+\.\d+\.\d+\.\d+)】'
            r'(?P<content>.*?)(?:》》)?'
            r'(?P<detail>》》.*)?$'  
        )

        ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
        non_printable = re.compile(r'[\x00-\x1F\x7F-\x9F]')

        with open(combined_log_path, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    clean_line = ansi_escape.sub('', line)
                    clean_line = non_printable.sub('', clean_line).strip()
                    if not clean_line:
                        continue
                    if clean_line.startswith("===="):
                        ws.append(["", "分隔线", ""])
                        continue
                    if clean_line.startswith("时间:"):
                        ws.append(["", clean_line.replace("开始", "").replace("结束", "").strip(), ""])
                        continue
                    match = log_pattern.match(clean_line)
                    if match:
                        ip = match.group('ip')
                        content = match.group('content').strip()
                        detail = match.group('detail') or ""
                        if detail:
                            ws.append([ip, "》》", detail[2:].strip()]) 
                        else:
                            ws.append([ip, content, ""])
                    else:
                        ws.append(["", clean_line, ""])
                        
                except Exception as e:
                    print(f"处理行时出错：{str(e)}")
                    raise
        try:
            wb.save(xlsx_path)
        except PermissionError:
            raise PermissionError("请关闭Excel文件后重试")
            
    except ImportError:
        print(f"{'错误：缺少openpyxl库，请执行 pip install openpyxl'}")
        raise
    except Exception as e:
        print(f"生成Excel失败：{str(e)}")
        if os.path.exists(xlsx_path):
            try: os.remove(xlsx_path)
            except: pass
        raise

def merge_nodelogs_to_combined(log_base):
    from collections import defaultdict
    combined_path = os.path.join(log_base, "combined.log")
    nodelog_dir = os.path.join(log_base, "nodelogs")
    
    category_stats = defaultdict(list)
    for category in os.listdir(nodelog_dir):
        category_dir = os.path.join(nodelog_dir, category)
        if os.path.isdir(category_dir):
            for filename in os.listdir(category_dir):
                if filename.endswith(".log"):
                    ip = filename.split(".log")[0]
                    if not re.match(r"^(\d{1,3}\.){3}\d{1,3}$", ip):
                        continue
                    category_stats[category].append((ip, os.path.join(category_dir, filename)))
    
    sorted_categories = sorted(category_stats.items(), key=lambda x: len(x[1]))
    
    log_files = []
    for category, files in sorted_categories:
        sorted_files = sorted(files, key=lambda x: tuple(map(int, x[0].split('.'))))
        log_files.append((category, len(sorted_files), sorted_files))
    
    with open(combined_path, "w", encoding="utf-8") as combined_file:
        for category, count, files in log_files:
            for ip, file_path in files:
                with open(file_path, "r", encoding="utf-8") as log_file:
                    combined_content = log_file.read()
                    combined_file.write(combined_content)
                    combined_file.write("\n" + "="*80 + "\n")

