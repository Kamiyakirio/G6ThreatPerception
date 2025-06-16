package com.tpp.threat_perception_platform.service;

import com.tpp.threat_perception_platform.param.MyParam;
import com.tpp.threat_perception_platform.param.SystemDetectParam;
import com.tpp.threat_perception_platform.pojo.Host;
import com.tpp.threat_perception_platform.response.ResponseResult;

import java.util.HashMap;
import java.util.List;

public interface HostService {
    public int saveHost(Host host);

    public ResponseResult findAll(MyParam param);
    public ResponseResult delete(Integer[] ids);

    public List<Host> listAll();

    public Host selectByPrimaryKey(Integer id);
    
    public Host selectByMacAddress(String macAddress);

    public HashMap<String,Object> hostDetect(HashMap<String,Object> data);



}
