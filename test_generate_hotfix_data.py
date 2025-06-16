# coding=utf-8
# Author: HSJ
# 2024/6/6 22:08
import requests
import datetime
import json
import calendar
import re
import pymysql

# 获取当前年份和日期
YEAR = str(datetime.datetime.now().year)
TODAY = datetime.datetime.now().strftime('%Y-%m-%d')
MONTH_IN_SHORT_EN = calendar.month_abbr[datetime.datetime.now().month]
THIS_MONTH_ID = YEAR + "-May"  # 示例中固定为 "Mar"，可根据需要调整
print(THIS_MONTH_ID)
print(YEAR)

# API 基础 URL 和 API 密钥
base_url = "https://api.msrc.microsoft.com/"
api_key = ""  # 替换为实际的 API 密钥

def get_cvrf_json():
    # 连接数据库
    db = pymysql.connect(
        host="localhost", port=3306, user="root", password="123456", db="new_threat_perception"
    )
    cur = db.cursor()

    # 构造请求 URL 和头部
    url = f"{base_url}cvrf/{THIS_MONTH_ID}?api-Version={YEAR}"
    headers = {'api-key': api_key, 'Accept': 'application/json'}

    # 发送请求
    response = requests.get(url, headers=headers)
    data = json.loads(response.content)

    # 遍历产品信息
    for each_product in data["ProductTree"]["FullProductName"]:
        product_id = each_product['ProductID']
        product_name = each_product['Value']

        # 检查产品 ID 是否已存在
        search_productid_sql = f"SELECT * FROM win_product_name WHERE product_id='{product_id}'"
        cur.execute(search_productid_sql)
        if cur.rowcount == 0:
            # 插入新产品信息
            insert_product_sql = f"INSERT INTO win_product_name VALUES(null, '{product_id}', '{product_name}', '{TODAY}')"
            cur.execute(insert_product_sql)
            db.commit()
        print('----------------------------------------------------------------')

    # 遍历漏洞信息
    for each_cve in data["Vulnerability"]:
        cve = each_cve["CVE"]
        if re.search('ADV', cve):
            continue

        kblist = []
        scorelist = []

        # 获取产品 ID 列表
        product_id_list = str(each_cve["ProductStatuses"][0]["ProductID"]).replace("'", "")
        product_id_list = product_id_list.replace("[", "").replace("]", "").replace(" ", "")

        # 获取 KB 编号
        for each_kb in each_cve["Remediations"]:
            try:
                kb_num = each_kb["Description"]["Value"]
                if re.search('Click to Run', kb_num) or re.search('Release Notes', kb_num):
                    continue
                kblist.append('KB{}'.format(kb_num))
            except Exception as e:
                print("kb", e)
        kblist = list(set(kblist))
        kblist = str(kblist).replace("'", "").replace("[", "").replace("]", "").replace(" ", "")

        # 获取 CVSS 分数
        for each_score in each_cve["CVSSScoreSets"]:
            try:
                scorelist.append(each_score["BaseScore"])
            except Exception as e:
                print("score", e)
        try:
            score_mean = format(sum(scorelist) / len(scorelist), '.1f')
        except Exception as e:
            print("score_mean", e)
            score_mean = 0

        # 插入 CVE 信息
        insert_cve_sql = f"INSERT INTO win_cve_db VALUES(null, '{cve}', '{score_mean}', '{product_id_list}', '{kblist}', '{THIS_MONTH_ID}', '{TODAY}')"
        print(insert_cve_sql)
        cur.execute(insert_cve_sql)
        db.commit()

    # 关闭数据库连接
    db.close()

if __name__ == '__main__':
    get_cvrf_json()