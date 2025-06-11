package com.tpp.threat_perception_platform.asset;

import java.util.Date;

/**
 * 
 * @TableName account
 */
public class Account {
    /**
     * 用户sid，主键
     */
    private String sid;

    /**
     * 
     */
    private String name;

    /**
     * 
     */
    private String fullName;

    /**
     * 
     */
    private Integer disabled;

    /**
     * 
     */
    private Integer lockout;

    /**
     * 
     */
    private Integer passwordChangeable;

    /**
     * 
     */
    private Integer passwordExpires;

    /**
     * 
     */
    private Integer passwordRequired;

    /**
     * 
     */
    private String hostName;

    /**
     * 
     */
    private Integer id;

    /**
     * 
     */
    private String macAddress;

    /**
     * 
     */
    private Date time;

    /**
     * 
     */
    private Integer sidType;

    /**
     * 
     */
    private String status;

    /**
     * 区分每次扫描
     */
    private Integer detectId;

    /**
     * 用户sid，主键
     */
    public String getSid() {
        return sid;
    }

    /**
     * 用户sid，主键
     */
    public void setSid(String sid) {
        this.sid = sid;
    }

    /**
     * 
     */
    public String getName() {
        return name;
    }

    /**
     * 
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * 
     */
    public String getFullName() {
        return fullName;
    }

    /**
     * 
     */
    public void setFullName(String fullName) {
        this.fullName = fullName;
    }

    /**
     * 
     */
    public Integer getDisabled() {
        return disabled;
    }

    /**
     * 
     */
    public void setDisabled(Integer disabled) {
        this.disabled = disabled;
    }

    /**
     * 
     */
    public Integer getLockout() {
        return lockout;
    }

    /**
     * 
     */
    public void setLockout(Integer lockout) {
        this.lockout = lockout;
    }

    /**
     * 
     */
    public Integer getPasswordChangeable() {
        return passwordChangeable;
    }

    /**
     * 
     */
    public void setPasswordChangeable(Integer passwordChangeable) {
        this.passwordChangeable = passwordChangeable;
    }

    /**
     * 
     */
    public Integer getPasswordExpires() {
        return passwordExpires;
    }

    /**
     * 
     */
    public void setPasswordExpires(Integer passwordExpires) {
        this.passwordExpires = passwordExpires;
    }

    /**
     * 
     */
    public Integer getPasswordRequired() {
        return passwordRequired;
    }

    /**
     * 
     */
    public void setPasswordRequired(Integer passwordRequired) {
        this.passwordRequired = passwordRequired;
    }

    /**
     * 
     */
    public String getHostName() {
        return hostName;
    }

    /**
     * 
     */
    public void setHostName(String hostName) {
        this.hostName = hostName;
    }

    /**
     * 
     */
    public Integer getId() {
        return id;
    }

    /**
     * 
     */
    public void setId(Integer id) {
        this.id = id;
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

    /**
     * 
     */
    public Date getTime() {
        return time;
    }

    /**
     * 
     */
    public void setTime(Date time) {
        this.time = time;
    }

    /**
     * 
     */
    public Integer getSidType() {
        return sidType;
    }

    /**
     * 
     */
    public void setSidType(Integer sidType) {
        this.sidType = sidType;
    }

    /**
     * 
     */
    public String getStatus() {
        return status;
    }

    /**
     * 
     */
    public void setStatus(String status) {
        this.status = status;
    }

    /**
     * 区分每次扫描
     */
    public Integer getDetectId() {
        return detectId;
    }

    /**
     * 区分每次扫描
     */
    public void setDetectId(Integer detectId) {
        this.detectId = detectId;
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
        Account other = (Account) that;
        return (this.getSid() == null ? other.getSid() == null : this.getSid().equals(other.getSid()))
            && (this.getName() == null ? other.getName() == null : this.getName().equals(other.getName()))
            && (this.getFullName() == null ? other.getFullName() == null : this.getFullName().equals(other.getFullName()))
            && (this.getDisabled() == null ? other.getDisabled() == null : this.getDisabled().equals(other.getDisabled()))
            && (this.getLockout() == null ? other.getLockout() == null : this.getLockout().equals(other.getLockout()))
            && (this.getPasswordChangeable() == null ? other.getPasswordChangeable() == null : this.getPasswordChangeable().equals(other.getPasswordChangeable()))
            && (this.getPasswordExpires() == null ? other.getPasswordExpires() == null : this.getPasswordExpires().equals(other.getPasswordExpires()))
            && (this.getPasswordRequired() == null ? other.getPasswordRequired() == null : this.getPasswordRequired().equals(other.getPasswordRequired()))
            && (this.getHostName() == null ? other.getHostName() == null : this.getHostName().equals(other.getHostName()))
            && (this.getId() == null ? other.getId() == null : this.getId().equals(other.getId()))
            && (this.getMacAddress() == null ? other.getMacAddress() == null : this.getMacAddress().equals(other.getMacAddress()))
            && (this.getTime() == null ? other.getTime() == null : this.getTime().equals(other.getTime()))
            && (this.getSidType() == null ? other.getSidType() == null : this.getSidType().equals(other.getSidType()))
            && (this.getStatus() == null ? other.getStatus() == null : this.getStatus().equals(other.getStatus()))
            && (this.getDetectId() == null ? other.getDetectId() == null : this.getDetectId().equals(other.getDetectId()));
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((getSid() == null) ? 0 : getSid().hashCode());
        result = prime * result + ((getName() == null) ? 0 : getName().hashCode());
        result = prime * result + ((getFullName() == null) ? 0 : getFullName().hashCode());
        result = prime * result + ((getDisabled() == null) ? 0 : getDisabled().hashCode());
        result = prime * result + ((getLockout() == null) ? 0 : getLockout().hashCode());
        result = prime * result + ((getPasswordChangeable() == null) ? 0 : getPasswordChangeable().hashCode());
        result = prime * result + ((getPasswordExpires() == null) ? 0 : getPasswordExpires().hashCode());
        result = prime * result + ((getPasswordRequired() == null) ? 0 : getPasswordRequired().hashCode());
        result = prime * result + ((getHostName() == null) ? 0 : getHostName().hashCode());
        result = prime * result + ((getId() == null) ? 0 : getId().hashCode());
        result = prime * result + ((getMacAddress() == null) ? 0 : getMacAddress().hashCode());
        result = prime * result + ((getTime() == null) ? 0 : getTime().hashCode());
        result = prime * result + ((getSidType() == null) ? 0 : getSidType().hashCode());
        result = prime * result + ((getStatus() == null) ? 0 : getStatus().hashCode());
        result = prime * result + ((getDetectId() == null) ? 0 : getDetectId().hashCode());
        return result;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(getClass().getSimpleName());
        sb.append(" [");
        sb.append("Hash = ").append(hashCode());
        sb.append(", sid=").append(sid);
        sb.append(", name=").append(name);
        sb.append(", fullName=").append(fullName);
        sb.append(", disabled=").append(disabled);
        sb.append(", lockout=").append(lockout);
        sb.append(", passwordChangeable=").append(passwordChangeable);
        sb.append(", passwordExpires=").append(passwordExpires);
        sb.append(", passwordRequired=").append(passwordRequired);
        sb.append(", hostName=").append(hostName);
        sb.append(", id=").append(id);
        sb.append(", macAddress=").append(macAddress);
        sb.append(", time=").append(time);
        sb.append(", sidType=").append(sidType);
        sb.append(", status=").append(status);
        sb.append(", detectId=").append(detectId);
        sb.append("]");
        return sb.toString();
    }
}