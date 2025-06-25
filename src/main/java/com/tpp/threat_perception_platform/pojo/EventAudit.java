package com.tpp.threat_perception_platform.pojo;

/**
 * 
 * @TableName event_audit
 */
public class EventAudit {
    /**
     * 
     */
    private Integer eventAuditId;

    /**
     * 审核系统事件
     */
    private Integer auditSystemEvents;

    /**
     * 审核登录事件
     */
    private Integer auditLogonEvents;

    /**
     * 审核对象访问
     */
    private Integer auditObjectAccess;

    /**
     * 审核特权使用
     */
    private Integer auditPrivilegeUse;

    /**
     * 审核策略更改
     */
    private Integer auditPolicyChange;

    /**
     * 审核账户管理
     */
    private Integer auditAccountManage;

    /**
     * 审核过程追踪
     */
    private Integer auditProcessTracking;

    /**
     * 审核目录服务访问
     */
    private Integer auditDSAccess;

    /**
     * 审核账户登录事件
     */
    private Integer auditAccountLogon;

    /**
     * 
     */
    private String type;

    /**
     * 
     */
    private String macAddress;

    /**
     * 
     */
    public Integer getEventAuditId() {
        return eventAuditId;
    }

    /**
     * 
     */
    public void setEventAuditId(Integer eventAuditId) {
        this.eventAuditId = eventAuditId;
    }

    /**
     * 审核系统事件
     */
    public Integer getAuditSystemEvents() {
        return auditSystemEvents;
    }

    /**
     * 审核系统事件
     */
    public void setAuditSystemEvents(Integer auditSystemEvents) {
        this.auditSystemEvents = auditSystemEvents;
    }

    /**
     * 审核登录事件
     */
    public Integer getAuditLogonEvents() {
        return auditLogonEvents;
    }

    /**
     * 审核登录事件
     */
    public void setAuditLogonEvents(Integer auditLogonEvents) {
        this.auditLogonEvents = auditLogonEvents;
    }

    /**
     * 审核对象访问
     */
    public Integer getAuditObjectAccess() {
        return auditObjectAccess;
    }

    /**
     * 审核对象访问
     */
    public void setAuditObjectAccess(Integer auditObjectAccess) {
        this.auditObjectAccess = auditObjectAccess;
    }

    /**
     * 审核特权使用
     */
    public Integer getAuditPrivilegeUse() {
        return auditPrivilegeUse;
    }

    /**
     * 审核特权使用
     */
    public void setAuditPrivilegeUse(Integer auditPrivilegeUse) {
        this.auditPrivilegeUse = auditPrivilegeUse;
    }

    /**
     * 审核策略更改
     */
    public Integer getAuditPolicyChange() {
        return auditPolicyChange;
    }

    /**
     * 审核策略更改
     */
    public void setAuditPolicyChange(Integer auditPolicyChange) {
        this.auditPolicyChange = auditPolicyChange;
    }

    /**
     * 审核账户管理
     */
    public Integer getAuditAccountManage() {
        return auditAccountManage;
    }

    /**
     * 审核账户管理
     */
    public void setAuditAccountManage(Integer auditAccountManage) {
        this.auditAccountManage = auditAccountManage;
    }

    /**
     * 审核过程追踪
     */
    public Integer getAuditProcessTracking() {
        return auditProcessTracking;
    }

    /**
     * 审核过程追踪
     */
    public void setAuditProcessTracking(Integer auditProcessTracking) {
        this.auditProcessTracking = auditProcessTracking;
    }

    /**
     * 审核目录服务访问
     */
    public Integer getAuditDSAccess() {
        return auditDSAccess;
    }

    /**
     * 审核目录服务访问
     */
    public void setAuditDSAccess(Integer auditDSAccess) {
        this.auditDSAccess = auditDSAccess;
    }

    /**
     * 审核账户登录事件
     */
    public Integer getAuditAccountLogon() {
        return auditAccountLogon;
    }

    /**
     * 审核账户登录事件
     */
    public void setAuditAccountLogon(Integer auditAccountLogon) {
        this.auditAccountLogon = auditAccountLogon;
    }

    /**
     * 
     */
    public String getType() {
        return type;
    }

    /**
     * 
     */
    public void setType(String type) {
        this.type = type;
    }

    /**
     * 
     */
    public String getMacAddress() {
        return macAddress;
    }

    /**
     * 
     */
    public void setMacAddress(String macAddress) {
        this.macAddress = macAddress;
    }

    @Override
    public boolean equals(Object that) {
        if (this == that) {
            return true;
        }
        if (that == null) {
            return false;
        }
        if (getClass() != that.getClass()) {
            return false;
        }
        EventAudit other = (EventAudit) that;
        return (this.getEventAuditId() == null ? other.getEventAuditId() == null : this.getEventAuditId().equals(other.getEventAuditId()))
            && (this.getAuditSystemEvents() == null ? other.getAuditSystemEvents() == null : this.getAuditSystemEvents().equals(other.getAuditSystemEvents()))
            && (this.getAuditLogonEvents() == null ? other.getAuditLogonEvents() == null : this.getAuditLogonEvents().equals(other.getAuditLogonEvents()))
            && (this.getAuditObjectAccess() == null ? other.getAuditObjectAccess() == null : this.getAuditObjectAccess().equals(other.getAuditObjectAccess()))
            && (this.getAuditPrivilegeUse() == null ? other.getAuditPrivilegeUse() == null : this.getAuditPrivilegeUse().equals(other.getAuditPrivilegeUse()))
            && (this.getAuditPolicyChange() == null ? other.getAuditPolicyChange() == null : this.getAuditPolicyChange().equals(other.getAuditPolicyChange()))
            && (this.getAuditAccountManage() == null ? other.getAuditAccountManage() == null : this.getAuditAccountManage().equals(other.getAuditAccountManage()))
            && (this.getAuditProcessTracking() == null ? other.getAuditProcessTracking() == null : this.getAuditProcessTracking().equals(other.getAuditProcessTracking()))
            && (this.getAuditDSAccess() == null ? other.getAuditDSAccess() == null : this.getAuditDSAccess().equals(other.getAuditDSAccess()))
            && (this.getAuditAccountLogon() == null ? other.getAuditAccountLogon() == null : this.getAuditAccountLogon().equals(other.getAuditAccountLogon()))
            && (this.getType() == null ? other.getType() == null : this.getType().equals(other.getType()))
            && (this.getMacAddress() == null ? other.getMacAddress() == null : this.getMacAddress().equals(other.getMacAddress()));
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((getEventAuditId() == null) ? 0 : getEventAuditId().hashCode());
        result = prime * result + ((getAuditSystemEvents() == null) ? 0 : getAuditSystemEvents().hashCode());
        result = prime * result + ((getAuditLogonEvents() == null) ? 0 : getAuditLogonEvents().hashCode());
        result = prime * result + ((getAuditObjectAccess() == null) ? 0 : getAuditObjectAccess().hashCode());
        result = prime * result + ((getAuditPrivilegeUse() == null) ? 0 : getAuditPrivilegeUse().hashCode());
        result = prime * result + ((getAuditPolicyChange() == null) ? 0 : getAuditPolicyChange().hashCode());
        result = prime * result + ((getAuditAccountManage() == null) ? 0 : getAuditAccountManage().hashCode());
        result = prime * result + ((getAuditProcessTracking() == null) ? 0 : getAuditProcessTracking().hashCode());
        result = prime * result + ((getAuditDSAccess() == null) ? 0 : getAuditDSAccess().hashCode());
        result = prime * result + ((getAuditAccountLogon() == null) ? 0 : getAuditAccountLogon().hashCode());
        result = prime * result + ((getType() == null) ? 0 : getType().hashCode());
        result = prime * result + ((getMacAddress() == null) ? 0 : getMacAddress().hashCode());
        return result;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(getClass().getSimpleName());
        sb.append(" [");
        sb.append("Hash = ").append(hashCode());
        sb.append(", eventAuditId=").append(eventAuditId);
        sb.append(", auditSystemEvents=").append(auditSystemEvents);
        sb.append(", auditLogonEvents=").append(auditLogonEvents);
        sb.append(", auditObjectAccess=").append(auditObjectAccess);
        sb.append(", auditPrivilegeUse=").append(auditPrivilegeUse);
        sb.append(", auditPolicyChange=").append(auditPolicyChange);
        sb.append(", auditAccountManage=").append(auditAccountManage);
        sb.append(", auditProcessTracking=").append(auditProcessTracking);
        sb.append(", auditDSAccess=").append(auditDSAccess);
        sb.append(", auditAccountLogon=").append(auditAccountLogon);
        sb.append(", type=").append(type);
        sb.append(", macAddress=").append(macAddress);
        sb.append("]");
        return sb.toString();
    }
}