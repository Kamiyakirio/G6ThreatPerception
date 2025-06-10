import wmi
import pythoncom
import json


def detect_account():
    c = wmi.WMI()
    account_list = []
    # 获取所有用户
    for user in c.Win32_UserAccount():
        user_dict = {
            "name": user.Name,
            "full_name": user.FullName,
            "sid": user.SID,
            "sid_type": user.SIDType,
            "status": user.Status,
            "disabled": user.Disabled,
            "lockout": user.Lockout,
            "password_changeable": user.PasswordChangeable,
            "password_expires": user.PasswordExpires,
            "password_required": user.PasswordRequired,
        }
        account_list.append(user_dict)
    # 去初始化

    # 转换成JSON字符串
    account_data = json.dumps(account_list)

    return account_data
