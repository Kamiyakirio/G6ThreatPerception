import json
from concurrent.futures import as_completed
from concurrent.futures.thread import ThreadPoolExecutor

from log_detect.log_analysis import log_analysis_result_send
import datetime

from system.pc_information import PcInfo
from utils.naming_convert import underscore_to_camelcase, rename_dict_key


def log_detect(data):

    # print(data)
    threads = []
    thread_pool = ThreadPoolExecutor(16)
    return_data = {"data": []}
    basic_info = {
        "host_name": data["host_name"],
        "mac_address": data["mac_address"],
        "id": data["id"],
    }
    # 校验mac地址的合法性，如果不是本机的mac地址，则不执行命令，并返回空
    # 实时获取本机的mac地址，并与配置文件中的mac地址进行对比，如果相同，则返回数据，否则返回空
    info = PcInfo()
    localhost_mac_address = info.get_info_dict()["mac_address"]
    # print(localhost_mac_address)
    if localhost_mac_address != data["mac_address"]:
        return ""
    else:
        return_data["info"] = {
            underscore_to_camelcase(k): v for k, v in basic_info.items()
        }

        if data["detect_log"]:
            t = thread_pool.submit(log_analysis, data)
            threads.append(t)

        for i in as_completed(threads):
            result = i.result()
            # 组装完整的 JSON 结构
            return_data["data"].append({"type": "log", "data": result})

        return_data["info"]["time"] = datetime.datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        return_data["info"]["start_time"] = data["start_time"]
        return_data["info"]["end_time"] = data["end_time"]

        return_data["info"] = rename_dict_key(
            return_data["info"], underscore_to_camelcase
        )

        # print(return_data)
        print("Detect ended!")

        # 🔥 最终返回为字符串
        return json.dumps(return_data, ensure_ascii=False)


def log_analysis(data):

    # 调用 log_risk_judge 函数进行测试
    print("\n开始分析日志...")
    result, start_time, end_time = log_analysis_result_send(data)

    # 处理结果
    if result:
        # 打印整个JSON结果
        print("\n完整JSON结果:")
        # print(json.dumps(result, ensure_ascii=False, indent=2))
        return result, start_time, end_time
    else:
        print("日志分析失败。")
        return ""


if __name__ == "__main__":
    # 获取当前时间
    end_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 计算1天前的时间
    start_time = (datetime.datetime.now() - datetime.timedelta(days=1)).strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    # 测试数据
    test_data = {
        "mac_address": "f5:d4:52:4a:2b:af",
        "host_name": "localhost",
        "id": 1,
        "start_time": start_time,
        "end_time": end_time,
        "detect_log": True,
        "type": "log",
    }
    # print(log_detect(test_data))
