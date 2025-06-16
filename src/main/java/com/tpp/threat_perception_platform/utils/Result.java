package com.tpp.threat_perception_platform.utils;

import java.util.HashMap;
import java.util.Map;

public class Result extends HashMap<String, Object> {

    public static Result success() {
        return new Result().put("code", 0).put("msg", "成功");
    }

    public static Result success(Object data) {
        return new Result().put("code", 0).put("msg", "成功").put("data", data);
    }

    public static Result error(String msg) {
        return new Result().put("code", -1).put("msg", msg);
    }

    public Result put(String key, Object value) {
        super.put(key, value);
        return this;
    }
}
