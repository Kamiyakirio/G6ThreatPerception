from scapy.all import *
import random

import time


def parse_ports(ports: Union[Any, str, int, list[int], None]) -> list[int]:
    """
    解析多种类型的端口参数，返回去重排序后的端口列表。
    支持 int, str（如"80,443,8000-8002"）, list[int], None。
    """
    DEFAULT_PORTS = [
        21,
        22,
        23,
        25,
        53,
        80,
        110,
        139,
        143,
        443,
        445,
        993,
        995,
        1723,
        3306,
        3389,
        8080,
    ]

    result_ports = set()

    if ports is None:
        return DEFAULT_PORTS

    if isinstance(ports, int):
        result_ports.add(ports)

    elif isinstance(ports, list):
        for p in ports:
            if isinstance(p, int):
                result_ports.add(p)
            else:
                raise ValueError(f"列表中包含非整数元素：{p}")

    elif isinstance(ports, str):
        segments = ports.split(",")
        for segment in segments:
            segment = segment.strip()
            if "-" in segment:
                try:
                    start, end = map(int, segment.split("-"))
                    if start > end:
                        raise ValueError(f"无效端口范围：{segment}")
                    result_ports.update(range(start, end + 1))
                except ValueError:
                    raise ValueError(f"端口范围格式错误：{segment}")
            else:
                try:
                    result_ports.add(int(segment))
                except ValueError:
                    raise ValueError(f"无效端口：{segment}")

    else:
        raise TypeError(f"不支持的端口类型：{type(ports)}")

    # 最终返回排序后的列表
    return sorted(p for p in result_ports if 1 <= p <= 65535)


def port_scan(
    host: str | list[str], ports: Any | str | int | list[int], skip_ping=True
):
    skip_list = []
    if type(host) == str:
        host = [host]
    if not skip_ping:
        for idx, i in enumerate(host):
            ping_packet = IP(dst=i) / ICMP()
            reply = sr1(ping_packet, timeout=3, verbose=False)

            if not reply:
                print(f"Host {i} is not reachable, will skip port scan for host {i}.")
                skip_list.append(i)

    ports = parse_ports(ports)
    for i in host:
        result = []
        if i not in skip_list:
            for port in ports:
                ip = IP(dst=i)
                syn_pack = TCP(
                    dport=port,
                    flags="S",
                    seq=random.randint(1, 2**31 - 1),
                )
                response = sr1(ip / syn_pack, timeout=1, verbose=False)
                if (
                    response
                    and "A" in response[TCP].flags
                    and "S" in response[TCP].flags
                ):
                    result.append(port)
            print(result)


if __name__ == "__main__":
    start_time = time.perf_counter()
    port_scan("192.168.253.134", "1-32767", False)
    end_time = time.perf_counter()
    print((end_time - start_time))
