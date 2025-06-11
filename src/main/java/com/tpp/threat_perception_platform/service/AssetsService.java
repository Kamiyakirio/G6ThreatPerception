package com.tpp.threat_perception_platform.service;

import com.tpp.threat_perception_platform.param.MyParam;
import com.tpp.threat_perception_platform.response.ResponseResult;

public interface AssetsService {

    public ResponseResult findAll(MyParam param);


    public ResponseResult accountList(MyParam param, String macAddress);

    public ResponseResult appList(MyParam param, String macAddress);

    public ResponseResult processList(MyParam param, String macAddress);

    public ResponseResult serviceList(MyParam param, String macAddress);


}