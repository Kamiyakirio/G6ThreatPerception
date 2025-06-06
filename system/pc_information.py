import psutil
import socket
import uuid
import platform
import os
import json


class PcInfo:
    """
    Get basic information of a pc.
    """

    def __init__(self):
        self.pc_name = socket.gethostname()

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # 这里只是建立一个连接，不会发送数据
        self.ip_address = s.getsockname()[0]  # 获取本机 IP

        self.os_name = platform.system()
        self.os_name_detailed = platform.version()
        self.os_bit = platform.architecture()[0]

        # 将 MAC 地址从十六进制转换为标准的格式（XX:XX:XX:XX:XX:XX）
        self.mac_address = ":".join(
            [
                "{:02x}".format((uuid.getnode() >> elements) & 0xFF)
                for elements in range(0, 2 * 6, 2)
            ][::-1]
        )

        self.cpu_info = platform.processor()

        if "Windows" in self.os_name:
            output = os.popen("wmic cpu get name").read().strip().replace("\n\n", "\n")
            self.cpu_info = output.split("\n")[1]  # 去掉标题行
        else:
            self.cpu_info = ""

        # Unit: MB
        self.memory_size = psutil.virtual_memory().total // 1024 // 1024

        pass

    def get_info_json(self):
        data = {
            "pcName": self.pc_name,
            "ip_address": self.ip_address,
            "os_name": self.os_name,
            "os_name_detailed": self.os_name_detailed,
            "os_bit": self.os_bit,
            "mac_address": self.mac_address,
            "cpu_info": self.cpu_info,
            "memory_size": self.memory_size,
        }
        return json.dumps(data, ensure_ascii=False)


if __name__ == "__main__":
    info = PcInfo()
    print(info.get_info_json())
