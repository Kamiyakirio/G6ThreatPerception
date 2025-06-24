package com.tpp.threat_perception_platform.pojo;

public class BaselineItemResult {
    private String name;            // 配置项名称
    private String standardValue;   // 标准值
    private String actualValue;     // 当前值
    private Integer status;         // 状态：1-合格，0-异常
    private String description;     // 说明
    private String type;           // 类型：system_access/event_audit/privilege_rights/system_security_option

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getStandardValue() {
        return standardValue;
    }

    public void setStandardValue(String standardValue) {
        this.standardValue = standardValue;
    }

    public String getActualValue() {
        return actualValue;
    }

    public void setActualValue(String actualValue) {
        this.actualValue = actualValue;
    }

    public Integer getStatus() {
        return status;
    }

    public void setStatus(Integer status) {
        this.status = status;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }
} 