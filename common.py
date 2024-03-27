# coding: utf-8
import base64
import binascii
import datetime
import hashlib
import ipaddress
import logging
import os
import random
import re
import socket
import string
import subprocess
import sys
import traceback
import urllib
from collections import OrderedDict
from typing import List
from urllib.parse import urlparse, urlunparse

# 上面是标准库，下面是第三方库库
import socks
# python3.8 -m pip install PySocks
from bs4 import BeautifulSoup, Tag


def choose_from_list(items):
    """
    返回一个选中的list。
    """
    while True:
        try:
            print("Available options:")
            for index, item in enumerate(items):
                print(f"{index} {item}")
            print(f"{len(items)} all")

            user_input = input("Choose your item(s) with index (comma-separated for multiple):\n")

            if user_input.lower() == 'all':
                return items

            selected_indices = [int(index.strip()) for index in user_input.split(',') if index.strip().isdigit()]

            if all(0 <= index < len(items) for index in selected_indices):
                return [items[index] for index in selected_indices]
            else:
                print("Invalid index number. Please try again.")

        except EOFError:
            sys.exit(0)
        except KeyboardInterrupt:
            sys.exit(0)
        except ValueError:
            print("Invalid input. Please enter valid index number(s).")


def choose_from_iterable(iterable):
    """
    返回一个选中的list。
    """
    ordered_iterable = iterable

    # 如果输入是字典，则转换为有序字典
    if isinstance(iterable, dict):
        ordered_iterable = OrderedDict(iterable)

    while True:
        try:
            print("Available options:")
            for index, item in enumerate(ordered_iterable):
                print(f"{index} {item}")
            print(f"{len(ordered_iterable)} all")

            user_input = input("Choose your item(s) with index (comma-separated for multiple):\n")

            if user_input.lower() == 'all':
                return list(ordered_iterable.values())

            selected_indices = [int(index.strip()) for index in user_input.split(',') if index.strip().isdigit()]

            if all(0 <= index < len(ordered_iterable) for index in selected_indices):
                selected_items = [list(ordered_iterable.values())[index] for index in selected_indices]
                return selected_items
            else:
                print("Invalid index number. Please try again.")

        except EOFError:
            sys.exit(0)
        except KeyboardInterrupt:
            sys.exit(0)
        except ValueError:
            print("Invalid input. Please enter valid index number(s).")


def get_file_content(file_path):
    encodings = ["utf-8", "gbk"]
    for encoding in encodings:
        try:
            with open(file_path, "r", encoding=encoding) as fp:
                return fp.read()
        except:
            continue
    return None


def get_full_path(path):
    if path.startswith("~"):
        path = os.path.expanduser(path)
    if path.startswith("./") or path.startswith(".\\"):
        path = os.path.abspath(path)
    return path


def clean_list(lines, spliter=None, do_strip=True, remove_empty=True):
    """
    如果有分割符，会对每行再进行分割
    默认对每个元素进行strip
    默认删除空字符串
    :param lines:
    :param spliter:可以是字符串，也可以是包含多个字符串的list、set等可迭代对象
    :param do_strip:
    :param remove_empty:
    :return:
    """
    if isinstance(lines, list):
        if spliter:
            if isinstance(spliter, str):
                lines = [item for line in lines for item in line.split(spliter)]
            if is_iterable_of_type(spliter, str):
                for sp_item in spliter:
                    lines = [item for line in lines for item in line.split(sp_item)]
        if do_strip:
            lines = [line.strip() for line in lines]
        if remove_empty and "" in lines:
            lines = [line for line in lines if line != ""]
        return lines
    return lines


def is_iterable_of_type(obj, obj_type):
    """
    判断传入的对象，是否是一个可迭代对象，而且其中的元素是某个python支持的类型。比如 一个元素都是str的list
    """
    # 确保传递的类型是正确的
    if not isinstance(obj_type, type):
        raise TypeError("obj_type must be a valid type")

    try:
        # 判断对象是否可迭代
        iter_obj = iter(obj)
    except TypeError:
        return False

    # 遍历迭代器中的每个元素，确保都是指定的类型
    for item in iter_obj:
        if not isinstance(item, obj_type):
            return False
    return True


def get_lines_from_file(file_path, spliter=";", do_strip=True, remove_empty=True):
    """
    从文件中读行，返回一个列表。
    如果有分割符，会对每行再进行分割
    默认对每个元素进行strip
    默认删除空字符串
    :param file_path:
    :param spliter:
    :param do_strip:
    :param remove_empty:
    :return:
    """
    encodings_to_try = ['utf-8', 'gbk']  # 尝试的编码列表

    for encoding in encodings_to_try:
        try:
            with open(file_path, 'r', encoding=encoding) as f:
                lines = f.readlines()
                return clean_list(lines, spliter, do_strip, remove_empty)
        except UnicodeDecodeError:
            continue
        except FileNotFoundError:
            print(f"File not found: {file_path}")
            return None
        except Exception as e:
            print(f"An error occurred: {e}")
            return None

    return None  # 如果都尝试失败，则返回 None


def get_lines_from_quote(text, spliter=";", do_strip=True, remove_empty=True):
    if not text or not isinstance(text, str):
        return []

    lines = text.splitlines()
    return clean_list(lines, spliter, do_strip, remove_empty)


def get_lines_from_console(spliter=";", do_strip=True, remove_empty=True):
    lines = []

    print("Enter multiple lines of text (Ctrl+D or Ctrl+Z to end):")
    while True:
        try:
            line = input()
            lines.append(line)
        except EOFError:
            break

    return clean_list(lines, spliter, do_strip, remove_empty)


def grep_domain_name(text: str, endswith: str = None) -> List[str]:
    """
    Extracts domain names from text that end with the specified suffix.

    :param text: The input text containing domain names.
    :param endswith: The suffix that the domain names should end with. If None, match all domains.
    :return: A list of domain names.
    """
    if endswith:
        domain_pattern = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9.-]*\.' + re.escape(endswith))
    else:
        domain_pattern = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]+')

    # 使用findall函数找到所有匹配的域名
    matches = domain_pattern.findall(text)

    # 返回匹配结果
    return matches


def grep_ipv4(text: str) -> List[str]:
    """
    Extracts valid IPv4 addresses from text.

    :param text: The input text containing IPv4 addresses.
    :return: A list of valid IPv4 addresses.
    """
    # IPv4 地址的正则表达式
    ipv4_pattern = re.compile(
        r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')

    # 使用 findall 函数找到所有匹配的 IPv4 地址
    ipv4_addresses = ipv4_pattern.findall(text)

    return ipv4_addresses


def grep_email(text: str, endswith: str = None) -> list:
    """
    Extracts email addresses from text.

    :param text: The input text containing email addresses.
    :param endswith: A suffix to filter email addresses by their domain.
    :return: A list of email addresses.
    """
    if endswith:
        reg = rf'[a-zA-Z0-9.\-_+#~!$&,;=:+]+@[a-zA-Z0-9.-]*{endswith}\b'
    else:
        reg = r'[a-zA-Z0-9.\-_+#~!$&,;=:+]+@[a-zA-Z0-9.-]+\.[a-zA-Z]+'
    reg_emails = re.compile(reg)
    emails = reg_emails.findall(text)
    return emails


def is_valid_domain(domain):
    domain_pattern = "^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\\.)+[A-Za-z]{2,6}$"
    return re.match(domain_pattern, domain) is not None


def is_valid_host(host):
    if not host:
        return False
    try:
        return is_valid_domain(host) or is_valid_ip(host)
    except:
        return False


def is_valid_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def is_valid_subnet(subnet):
    '''
    strict =False，因为想要 192.168.1.1/27这个格式返回true
    :param subnet:
    :return:
    '''
    try:
        ipaddress.ip_network(subnet, strict=False)
        return True
    except ValueError:
        return False


def is_valid_domain_by_query(host):
    try:
        socket.getaddrinfo(host, None)
        return True
    except socket.gaierror:
        return False


def is_valid_port(port):
    try:
        p = int(port)
        if 0 <= p <= 65535:
            return True
    except:
        pass
    return False


def get_ip_list_of_subnet(subnet):
    try:
        tmp = ipaddress.ip_network(subnet, strict=False)
        result = [item.__str__() for item in tmp.hosts()]
        return result
    except ValueError:
        return []


def get_logger(log_file_name='logger.log'):
    """
    # https://stackoverflow.com/questions/7016056/python-logging-not-outputting-anything
    # 只是将handler的level改成debug是不够的，还需要设置logger本身的level。logger是上游，handler是下游
    :param log_file_name:
    :return:
    """
    formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(message)s')

    # 使用basicConfig设置全局的日志级别
    logging.basicConfig(level=logging.DEBUG)

    # 创建logger
    logger = logging.getLogger('main')

    # 创建和设置StreamHandler和FileHandler
    handlers = [logging.StreamHandler(sys.stdout), logging.FileHandler(log_file_name, encoding="utf-8")]
    for handler in handlers:
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger


def gen_random_str(length, include_uppercase=True, include_lowercase=True, include_digits=True,
                   include_special_chars=False):
    chars = ''
    if include_uppercase:
        chars += string.ascii_uppercase
    if include_lowercase:
        chars += string.ascii_lowercase
    if include_digits:
        chars += string.digits
    if include_special_chars:
        chars += string.punctuation

    if not chars:
        raise ValueError("At least one character type must be included")

    return ''.join(random.choice(chars) for _ in range(length))


def highlight_print(content, tips=""):
    if not tips:
        tips = ""
    print()
    print(("#" * 10 + "{}" + "#" * 10).format(tips))
    print(content)
    print("#" * (20 + len(str(tips))))
    print()


def set_socks_proxy(proxy_host, proxy_port):
    """
    设置全局的 SOCKS 代理，适用于所有套接字操作。
    socks.set_default_proxy()  # 取消代理设置
    """
    try:
        import socks
        import socket
        proxy_port = int(proxy_port)
        print("set proxy: {}:{}".format(proxy_host, proxy_port))
        socks.set_default_proxy(socks.SOCKS5, proxy_host, proxy_port)
        socket.socket = socks.socksocket
        return True
    except:
        print("set socks proxy failed!!!")
        return False


def is_using_socks_proxy():
    """
    检测当前程序是否使用了 SOCKS 代理。

    :return: 如果使用了 SOCKS 代理，返回 True；否则返回 False。
    """

    import socket
    return socket.socket == socks.socksocket


def get_cookie_dict(cookie_str):
    """
    将字符串格式的cookie转换为字典格式，方便在requests包中使用
    """
    if not isinstance(cookie_str, str):
        raise TypeError("Input must be a string")
    result = {}
    lines = cookie_str.splitlines()
    for line in lines:
        if line.lower().startswith("cookie:"):
            line = line.split(":", 1)[1]
        for item in line.split(";"):
            item = item.strip()
            if "=" in item:
                key, value = item.split("=", 1)
                result[key.strip()] = value.strip()
    return result


def get_base_url(url):
    '''
    return 末尾不包含/
    引用方法:
    from 包名处（模块名称）.文件名称 import 函数名称
    包或者模块，是指含有__init__.py的文件夹
    '''
    parsed_url = urlparse(url)
    base_url = urlunparse((parsed_url.scheme, parsed_url.netloc, '', '', '', ''))
    return base_url


def get_default_port(protocol: str) -> int:
    """
    Get the default port number for a given protocol.

    :param protocol: The protocol name (e.g., 'http', 'ftp', 'ssh', etc.).
    :return: The default port number for the protocol.
    """
    try:
        port = socket.getservbyname(protocol)
        return port
    except OSError as e:
        return -1


def get_host_port(target: str) -> tuple:
    """
    Extracts host and port from a target string.

    Possible target formats:
    - "ssh://127.0.0.1"
    - "127.0.0.1:8899"
    - "http://127.84.20:81"
    - "ftp://example.com:2121/path/to/file"
    - "sftp://user:pass@localhost:2222/some/path"

    :param target: The target string containing host and port information.
    :return: A tuple containing host and port.
    """

    # Check input types
    if not isinstance(target, str):
        raise TypeError("Target must be a string")

    try:
        # Parse the target URL
        parsed = urlparse(target)

        # Extract host and port
        host = parsed.hostname
        port = parsed.port
        protocol = parsed.scheme

        # Use default port if not specified
        if port is None or port == -1:
            port = get_default_port(protocol)

        # Return the result
        return host, port
    except Exception as e:
        traceback.print_exc()

    try:
        # Initialize variables
        port = -1

        # Remove protocol part
        if "://" in target:
            protocol, target = target.split("://", 1)
            port = get_default_port(protocol)

        # Remove username and password part
        if "@" in target:
            target = target.split("@", 1)[1]

        # Extract host and port
        if ":" in target:
            target, port_part = target.split(":", 1)
            if "/" in port_part:
                port_str = port_part.split("/", 1)[0]
            else:
                port_str = port_part
        if "/" in target:
            target = target.split("/", 1)[0]
        # Return the result
        try:
            port = int(port_str)
        except:
            pass
        return target, port
    except Exception as e:
        traceback.print_exc()
        return None, None


def url_encode(url):
    return urllib.parse.quote(url)


def url_decode(url):
    return urllib.parse.unquote(url)


def get_input_values(*arg_name):
    """
    从用户输入获取多个变量的值，类似如下的用法
    get_input_values("param1", "param2", "param3")
    :param arg_name:
    :return: 返回参数名和值的字典
    """
    result = dict()  # 还是用dict类型，结果不容易出错
    # 运行程序时，有参数传递，那么就直接使用
    if len(sys.argv) > len(arg_name):
        for i, arg in enumerate(arg_name):
            result[arg] = sys.argv[i + 1]
    else:  # 没有参数传递，要求用户输入
        for arg in arg_name:
            if arg is None or not isinstance(arg, str):
                continue
            arg_value = input(f"Enter [{arg}] value: ")
            result[arg] = arg_value
    return result


def get_textarea_contents(html, name=None):
    # Parse the HTML with BeautifulSoup
    soup = BeautifulSoup(html, 'html.parser')

    if name:
        # Find all <textarea> tags with the specified name attribute and extract their content
        textarea_contents = [textarea.text.strip() for textarea in soup.select(f'textarea[name="{name}"]')]
    else:
        # Find all <textarea> tags and extract their content
        textarea_contents = [textarea.text.strip() for textarea in soup.find_all('textarea')]

    return textarea_contents


def get_content_by_class(html, class_name):
    """
    根据
    :param html:
    :param class_name:
    :return:
    """
    # 使用 BeautifulSoup 解析 HTML
    soup = BeautifulSoup(html, 'html.parser')

    # 使用 CSS 选择器定位元素
    elements = soup.select(f'.{class_name}')

    # 提取元素的内容
    content = [element.get_text() for element in elements]

    return content


def get_content_by_element(html, element_name):
    # 使用 BeautifulSoup 解析 HTML
    soup = BeautifulSoup(html, 'html.parser')

    # 使用 CSS 选择器定位元素
    elements = soup.select(element_name)

    # 提取元素的内容
    content = [element.get_text() for element in elements]

    return content


def get_element_text(element):
    """
    获取BeautifulSoup的Tag对象，也就是HTML元素的文本内外，比如textarea中的字符串
    :param element:
    :return:
    """
    if isinstance(element, Tag):
        return element.get_text()
    elif hasattr(element, '__iter__'):
        result = []
        for item in element:
            result.append(get_element_text(item))
        return result


def get_element_attr(element, attr_name):
    """
    获取BeautifulSoup的Tag对象，也就是HTML元素的属性值
    :param element:
    :param attr_name:
    :return:
    """
    if isinstance(element, Tag):
        return element.get(str(attr_name).lower())
    elif hasattr(element, '__iter__'):
        result = []
        for item in element:
            result.append(get_element_attr(item, attr_name))
        return result


def find_elements(html, name, keywords: list = [], startswith=None, endswith=None):
    """
    HTML元素指的是从开始标签（start tag）到结束标签（end tag）的所有代码。BeautifulSoup的Tag对象（即元素）
    元素可拥有属性，属性总是以名称/值对的形式出现，比如：name="value"。
    class、id等是大多数HTML元素都有的属性
    <input checkDependsOn="credentialsId" checkMethod="post" checkUrl="/job/" name="_.url" placeholder="" type="text" class="jenkins-input validated  " value="">
    :param html:
    :param keywords: 关键词列表，将整个元素当作字符串看待，字符串需要包含所有的关键词
    :param name: 的作用对象是tag的名称，比如input、head等
    :return Tag对象的list
    """

    result = []

    if keywords is None:
        keywords = []
    if not isinstance(html, str):
        html = str(html)
    soup = BeautifulSoup(html, 'html.parser')

    elements = soup.find_all(name=name)

    # 使用集合来加速关键词匹配
    keywords_set = set(keywords)
    for element in elements:
        # 将元素转换为字符串，然后检查关键词是否在其中
        element_str = str(element)
        if any(keyword not in element_str for keyword in keywords_set):
            continue
        if startswith and not element_str.startswith(startswith):
            continue
        if endswith and not element_str.endswith(endswith):
            continue
        result.append(element)
    return result


def get_full_path(path):
    if path.startswith("~"):
        path = os.path.expanduser(path)
    if path.startswith("./") or path.startswith(".\\"):
        path = os.path.abspath(path)
    return path


def is_file_path_by_pattern(path):
    # 定义常见文件路径的正则表达式模式
    path_patterns = [
        r'^[a-zA-Z]:\\[^:*?"<>|\r\n]*$',  # Windows 绝对路径
        r'^[a-zA-Z]:/[^:*?"<>|\r\n]*$',  # Windows 绝对路径（斜杠）
        r'^/[^:*?"<>|\r\n]*$',  # Linux/MacOS 绝对路径
        r'^\.[a-zA-Z0-9_/-]*$',  # 相对路径
        r'^\.\.[a-zA-Z0-9_/-]*$'  # 相对路径（上级目录）
    ]

    # 使用正则表达式匹配路径
    for pattern in path_patterns:
        if re.match(pattern, path):
            return True

    # 如果没有匹配任何模式，则判定为无效路径
    return False


def get_ip(host):
    try:
        return socket.gethostbyname(host)
    except:
        return None


def startswith_regex(pattern, text):
    """
    尝试从字符串的[开头]匹配模式，如果匹配成功则返回True，否则返回False
    """
    match = re.match(pattern, text)
    if match:
        return True
    else:
        return False


def extract_between(text, start, end, case_sensitive=True, multiline=False):
    """
    提取两个字符串之间的内容，返回一个列表。
    :param text: 待提取的文本。
    :param start: 起始字符串。
    :param end: 结束字符串。
    :param case_sensitive: 是否区分大小写，默认为True（区分大小写）。
    :param multiline: 是否启用多行模式，默认为False（单行模式）。
    :return: 匹配到的内容列表。
    """
    # 根据是否区分大小写设置 re.IGNORECASE 标志
    flags = 0 if case_sensitive else re.IGNORECASE
    # 根据是否启用多行模式设置 re.DOTALL 标志
    flags |= re.DOTALL if multiline else 0
    pattern = re.escape(start) + r"(.*?)" + re.escape(end)
    matches = re.findall(pattern, text, flags=flags)
    return matches


def grep_between(text, start, end, case_sensitive=True, multiline=False):
    """
    同extract_between
    """
    return extract_between(text, start, end, case_sensitive, multiline)


def findfirst_regex(pattern, text):
    """
    在整个字符串中搜索匹配，如果找到则返回一个匹配对象，否则返回None
    """
    if not (pattern and text):
        return None
    search_result = re.search(pattern, text)
    if search_result:
        return search_result.group(0)
    return None


# 使用re.findall查找所有匹配
def findall_regex(pattern, text):
    """
    <td><a href="(.*?)" class="model-link inside">
    根据正则表达式提取所有匹配的内容，返回一个列表
    """
    if not (pattern and text):
        return []
    result_list = re.findall(pattern, text)
    return result_list or []  # 如果result_list为空，则返回一个空列表


def replaceall_regex(pattern, replaceto, text):
    """
    将正则表达式匹配到的内容替换为replaceto的内容，返回替换后的完整文本
    """
    if not (pattern and replaceto and text):
        return text
    new_text = re.sub(pattern, replaceto, text)
    return new_text


def get_base_url(url):
    """
    return 末尾不包含/，类似http请求的Origin header
    Origin: https://www.example.com
    Referer: https://www.example.com/user/login
    引用方法:
    from 包名处（模块名称）.文件名称 import 函数名称
    包或者模块，是指含有__init__.py的文件夹
    """
    parsed_url = urlparse(url)
    base_url = urlunparse((parsed_url.scheme, parsed_url.netloc, '', '', '', ''))
    return base_url


def combine_urls(page_url, relative_urls):
    """
    这个函数的作用是拼接页面的URL，和html中点击href链接的逻辑一致：
    如果href的值以斜杠（/）开头，则表示该链接是相对于站点根目录的路径，而如果href的值不以斜杠开头，则表示该链接是相对于当前页面的路径
    :page_url 页面URL，
    :relative_urls 访问页面URL获得的HTML中的href值
    """
    result = []
    base_url = get_base_url(page_url)

    for rel_url in relative_urls:
        if rel_url.startswith("/"):
            full_url = base_url + rel_url
        else:
            full_url = page_url.rstrip("/") + "/" + rel_url.lstrip("/")
        result.append(full_url)

    return result


def contains_any(string, keywords):
    """
    判断string是否包含任何一个关键词
    """
    if isinstance(keywords, str):
        return keywords in string
    if isinstance(keywords, (list, set)):
        for keyword in keywords:
            if keyword in string:
                return True
    return False


def print_all_str_vars(keywords_to_exclude=None):
    """
    打印用户定义的所有字符串变量，可以设置关键词根据变量名进行排除
    """
    if keywords_to_exclude is None:
        keywords_to_exclude = {}
    all_variables = globals()

    for var_name, var_value in all_variables.items():
        if not isinstance(var_value, str):
            continue
        if var_name.startswith("__") and var_name.endswith("__"):
            continue
        if contains_any(var_name, keywords_to_exclude):
            continue
        else:
            print(var_value)


def split_line(line):
    """
    将一行字符串分割成多个部分，连续的tab和空格都当作一个分隔符
    testcase = "This\tis   \t  a\t\t  test 	  string\t"
    testcase = "aaa	bbb"
    :param line:
    :return:
    """
    # parts = re.split(r'\s+|\t+', line)
    parts = line.split()
    # 字符串的split函数本身就有这样的能力
    return parts


def md5(input_string):
    # 创建一个 MD5 哈希对象
    md5_hash = hashlib.md5()

    # 更新哈希对象以包含输入字符串的字节表示
    md5_hash.update(input_string.encode('utf-8'))

    # 获取 MD5 哈希值的十六进制表示
    md5_hex = md5_hash.hexdigest()

    return md5_hex


def get_time_str():
    """
    返回当前时间的字符串，常用于文件名
    :return:
    """
    current_time = datetime.datetime.now()
    formatted_time = current_time.strftime("%Y_%m_%d_%H_%M_%S_%f")[:-3]
    return formatted_time


def run_external_program(command):
    """
    注意，要执行的命令、脚本，基本都要求绝对路径
    :param command:
    :return:
    """
    try:
        # Run the external program and capture its output
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)

        # Check if the command was successful (return code 0)
        if result.returncode == 0:
            # Return the standard output
            return result.stdout.strip()
        else:
            # If the command failed, print the error message
            print(f"Error: {result.stderr.strip()}")
            return None

    except Exception as e:
        print(f"An error occurred: {e}")
        return None


def deduplicate_list(input_list):
    # 使用OrderedDict.fromkeys()去重，并保持原始顺序
    deduplicated_dict = OrderedDict.fromkeys(input_list)

    # 将字典的键转换回列表
    deduplicated_list = list(deduplicated_dict.keys())

    return deduplicated_list


def is_hex_code(input_str):
    """
    hello -- 68656C6C6F
    :param input_str:
    :return:
    """
    return re.match(r"^[0-9a-fA-F]+$", input_str) is not None


def hex_code_to_byte_array(hex_code):
    r"""
    68656C6C6F --- b'hello'
    1112136162 --- b'\x11\x12\x13ab'
    可以打印的字符直接以字符表示，不行的用\x加code
    :param hex_code:
    :return:
    """
    return bytes.fromhex(hex_code)


def byte_array_to_hex_code(byte_array):
    """
    使用方法
    byte_array_to_hex_code(b"hello") -- bytes can only contain ASCII literal characters.
    byte_array_to_hex_code("hello中文".encode())
    :param byte_array:
    :return:
    """
    # 使用 binascii.hexlify 将字节数组转换为 hex code
    hex_code = binascii.hexlify(byte_array).decode()
    return hex_code


def is_base64(input_str):
    try:
        base64.b64decode(input_str)
        return True
    except ValueError:
        return False


def base64_encode(data):
    """
    传入的参数可以是 str 或者 byte array格式
    encode --- str to byte array
    decode --- byte array to str
    :param data:
    :return:
    """
    if isinstance(data, str):
        data = data.encode()

    # 进行 Base64 编码
    encoded_data = base64.b64encode(data).decode()
    return encoded_data


def base64_decode(data):
    """
    解码后，如果转化为字符串就返回字符串，否则就返回byte[]
    :param data:
    :return:
    """
    # 尝试解码成字符串
    try:
        decoded_str = base64.b64decode(data).decode()
        return decoded_str
    except UnicodeDecodeError:
        # 解码成字符串失败，返回字节数组
        decoded_bytes = base64.b64decode(data)
        return decoded_bytes
    except Exception:
        return None


def get_files_in_dir(directory, extensions=None, include_subdir=True):
    """
    获取目录下的所有文件。

    参数：
    - directory: 目标目录的路径。
    - extensions: 文件后缀过滤列表，例如 ['.txt', '.pdf']，默认为 None。
    - include_subdir: 是否遍历子目录，True 为遍历，False 为不遍历，默认为 True。

    返回：
    包含所有文件路径的列表。
    """
    files = []

    extensions = tuple(extensions) if extensions else None

    def is_valid_file(filename):
        return extensions is None or filename.endswith(extensions)

    if include_subdir:
        # 遍历目录及其子目录
        for root, _, filenames in os.walk(directory):
            for filename in filenames:
                if is_valid_file(filename):
                    files.append(os.path.join(root, filename))
    else:
        # 不遍历子目录，直接获取目录下的文件列表
        files = [os.path.join(directory, filename) for filename in os.listdir(directory)
                 if os.path.isfile(os.path.join(directory, filename)) and is_valid_file(filename)]

    return files


if __name__ == '__main__':
    # 测试函数
    text = "Visit us at htsstps://xxx.example.com \n\r" \
           "or htaatp://sub.example.co.uk for more information."
    domains = grep_between(text, "htsstps", "information", multiline=True)
    print(domains)
