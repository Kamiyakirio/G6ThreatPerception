package com.tpp.threat_perception_platform.pojo;

import java.util.Date;

/**
 * 
 * @TableName system_detect
 */
public class SystemDetect {
    /**
     * 探测结果id,自增主键
     */
    private Integer sid;

    /**
     * 
     */
    private String macAddress;

    /**
     * 探测项目名称
     */
    private String detectProgram;

    /**
     * 
     */
    private String riskLevel;

    /**
     * 
     */
    private String details;

    /**
     * 
     */
    private String suggest;

    /**
     * 标注同一主机的探测次数
     */
    private Integer sDetectId;

    /**
     * 
     */
    private Date detectTime;

    /**
     * 探测结果id,自增主键
     */
    public Integer getSid() {
        return sid;
    }

    /**
     * 探测结果id,自增主键
     */
    public void setSid(Integer sid) {
        this.sid = sid;
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
     * 探测项目名称
     */
    public String getDetectProgram() {
        return detectProgram;
    }

    /**
     * 探测项目名称
     */
    public void setDetectProgram(String detectProgram) {
        this.detectProgram = detectProgram;
    }

    /**
     * 
     */
    public String getRiskLevel() {
        return riskLevel;
    }

    /**
     * 
     */
    public void setRiskLevel(String riskLevel) {
        this.riskLevel = riskLevel;
    }

    /**
     * 
     */
    public String getDetails() {
        return details;
    }

    /**
     * 
     */
    public void setDetails(String details) {
        this.details = details;
    }

    /**
     * 
     */
    public String getSuggest() {
        return suggest;
    }

    /**
     * 
     */
    public void setSuggest(String suggest) {
        this.suggest = suggest;
    }

    /**
     * 标注同一主机的探测次数
     */
    public Integer getsDetectId() {
        return sDetectId;
    }

    /**
     * 标注同一主机的探测次数
     */
    public void setsDetectId(Integer sDetectId) {
        this.sDetectId = sDetectId;
    }

    /**
     * 
     */
    public Date getDetectTime() {
        return detectTime;
    }

    /**
     * 
     */
    public void setDetectTime(Date detectTime) {
        this.detectTime = detectTime;
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
        SystemDetect other = (SystemDetect) that;
        return (this.getSid() == null ? other.getSid() == null : this.getSid().equals(other.getSid()))
            && (this.getMacAddress() == null ? other.getMacAddress() == null : this.getMacAddress().equals(other.getMacAddress()))
            && (this.getDetectProgram() == null ? other.getDetectProgram() == null : this.getDetectProgram().equals(other.getDetectProgram()))
            && (this.getRiskLevel() == null ? other.getRiskLevel() == null : this.getRiskLevel().equals(other.getRiskLevel()))
            && (this.getDetails() == null ? other.getDetails() == null : this.getDetails().equals(other.getDetails()))
            && (this.getSuggest() == null ? other.getSuggest() == null : this.getSuggest().equals(other.getSuggest()))
            && (this.getsDetectId() == null ? other.getsDetectId() == null : this.getsDetectId().equals(other.getsDetectId()))
            && (this.getDetectTime() == null ? other.getDetectTime() == null : this.getDetectTime().equals(other.getDetectTime()));
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((getSid() == null) ? 0 : getSid().hashCode());
        result = prime * result + ((getMacAddress() == null) ? 0 : getMacAddress().hashCode());
        result = prime * result + ((getDetectProgram() == null) ? 0 : getDetectProgram().hashCode());
        result = prime * result + ((getRiskLevel() == null) ? 0 : getRiskLevel().hashCode());
        result = prime * result + ((getDetails() == null) ? 0 : getDetails().hashCode());
        result = prime * result + ((getSuggest() == null) ? 0 : getSuggest().hashCode());
        result = prime * result + ((getsDetectId() == null) ? 0 : getsDetectId().hashCode());
        result = prime * result + ((getDetectTime() == null) ? 0 : getDetectTime().hashCode());
        return result;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(getClass().getSimpleName());
        sb.append(" [");
        sb.append("Hash = ").append(hashCode());
        sb.append(", sid=").append(sid);
        sb.append(", macAddress=").append(macAddress);
        sb.append(", detectProgram=").append(detectProgram);
        sb.append(", riskLevel=").append(riskLevel);
        sb.append(", details=").append(details);
        sb.append(", suggest=").append(suggest);
        sb.append(", sDetectId=").append(sDetectId);
        sb.append(", detectTime=").append(detectTime);
        sb.append("]");
        return sb.toString();
    }
}