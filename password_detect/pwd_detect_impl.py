import os
from impacket.examples.utils import parse_target
from impacket.smbconnection import SMBConnection
from detect.asset_detect_impl import detect_account

# 获取当前文件所在目录
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PASSWORD_FILE = os.path.join(BASE_DIR, "weak_passwords.txt")


def read_weak_passwords():
    """从文件中读取弱口令列表"""
    if not os.path.exists(PASSWORD_FILE):
        raise FileNotFoundError(f"文件 {PASSWORD_FILE} 不存在")

    with open(PASSWORD_FILE, "r", encoding="utf-8") as f:
        # 去除空行和注释行，并去除前后空格
        passwords = [
            line.strip()
            for line in f.readlines()
            if line.strip() and not line.startswith("#")
        ]
    return passwords


def pwd_detect():
    account_list = []
    pwdlist = read_weak_passwords()  # 从文件中加载弱口令
    print(f"Loaded {len(pwdlist)} weak passwords.")

    account_data = detect_account()
    # 如果用户的全名(full_name)为空，则使用用户名（name）;否则使用全名
    userlist = [
        user["name"] if user["full_name"] == "" else user["full_name"]
        for user in account_data["data"]
    ]
    print("User list:", userlist)

    address = "127.0.0.1"

    for user in userlist:
        for pwd in pwdlist:
            target = "{}:{}@{}".format(user, pwd, address)
            domain, username, password, address = parse_target(target)
            target_ip = address
            domain = ""
            lmhash = ""
            nthash = ""

            try:
                smbClient = SMBConnection(address, target_ip, sess_port=int(445))
                smbClient.login(username, password, domain, lmhash, nthash)
                print(username + " 登录成功！")
                user_dict = {"name": username}
                if user_dict not in account_list:
                    account_list.append(user_dict)
                # 成功后直接进入下一个账号的检测，比如当前账号第一次登录成功，则直接进入下一个账号的检测
                break
            except Exception as e:
                pass

    return account_list
