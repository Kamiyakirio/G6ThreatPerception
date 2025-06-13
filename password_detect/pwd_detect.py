from concurrent.futures import ThreadPoolExecutor, as_completed
from password_detect.pwd_crack import pwd_detect
from system.pc_information import PcInfo
from utils.naming_convert import underscore_to_camelcase

import json
import datetime


def password_detect(data):
    print(data)
    threads = []
    thread_pool = ThreadPoolExecutor(16)
    return_data = {"data": []}
    basic_info = {
        "host_name": data["host_name"],
        "mac_address": data["mac_address"],
        "id": data["id"],
    }
    #校验mac地址的合法性，如果不是本机的mac地址，则不执行命令，并返回空
    #实时获取本机的mac地址，并与配置文件中的mac地址进行对比，如果相同，则返回数据，否则返回空
    info = PcInfo()
    localhost_mac_address = info.get_info_dict()["mac_address"]
    print(localhost_mac_address)
    if localhost_mac_address != data["mac_address"]:
        return ""
    else:
        return_data["info"] = {underscore_to_camelcase(k): v for k, v in basic_info.items()}

        if data["detect_pwd"]:
            t = thread_pool.submit(pwd_detect)
            threads.append(t)

        for i in as_completed(threads):
            result = i.result()
            # 组装完整的 JSON 结构
            return_data["data"].append({
                "type": "pwd",
                "data": result
            })

        return_data["info"]["time"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(return_data)
        print("Detect ended!")

        # 🔥 最终返回为字符串
        return json.dumps(return_data, ensure_ascii=False)

if __name__ == "__main__":
    test_data = {
        "host_name": "localhost",
        "mac_address": "f5:d4:52:4a:2b:ae",
        "id": "test123",
        "detect_pwd": True
    }
    password_detect(test_data)
