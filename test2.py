# 初始化
import json

import pythoncom
import self
import wmi

pythoncom.CoInitialize()
# 创建WMI客户端
c = wmi.WMI()
# 获取补丁信息
hotfixes = c.query("SELECT HotFixID FROM Win32_QuickFixEngineering")
# 组装补丁ID
hotfix_list = []
for hotfix in hotfixes:
    data = {
    # 'mac': self.__data['mac'],
    'hotfixId': hotfix.HotFixID
    }
hotfix_list.append(data)
# 去初始化
# pythoncom.CoUninitialize()
# 转换成JSON数据
data = json.dumps(hotfix_list)
print(data)
# 发送到队列
# self.__mq.produce_hotfix_data(data)