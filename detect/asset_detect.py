from detect.asset_detect_impl import (
    detect_account,
    detect_service,
    detect_process,
    detect_app,
)
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.naming_convert import underscore_to_camelcase

import json
import datetime


def asset_detect(data):
    threads = []
    thread_pool = ThreadPoolExecutor(16)

    return_data = {"data": []}
    basic_info = {
        "host_name": data["host_name"],
        "mac_address": data["mac_address"],
        "id": data["id"],
        "type": "assets",
    }
    return_data["info"] = {underscore_to_camelcase(k): v for k, v in basic_info.items()}

    if data["detect_account"]:
        t = thread_pool.submit(detect_account)
        threads.append(t)
    if data["detect_service"]:
        t = thread_pool.submit(detect_service)
        threads.append(t)
    if data["detect_process"]:
        t = thread_pool.submit(detect_process)
        threads.append(t)
    if data["detect_app"]:
        t = thread_pool.submit(detect_app)
        threads.append(t)

    for i in as_completed(threads):
        result = i.result()
        return_data["data"].append({"type": result["type"], "data": result["data"]})

    return_data["info"]["time"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print("Detect all ended!")

    return json.dumps(return_data)
