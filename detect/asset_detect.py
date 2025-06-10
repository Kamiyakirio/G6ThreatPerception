from detect.detects import detect_account, detect_service, detect_process, detect_app


def asset_detect(data):
    print(data)
    if data["detect_account"]:
        detect_account()
    if data[""]