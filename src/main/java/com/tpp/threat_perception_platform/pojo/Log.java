package com.tpp.threat_perception_platform.pojo;

import java.util.Date;

/**
 *
 * @TableName log
 */
public class Log {
    /**
     *
     */
    private Long logId;

    /**
     * MAC地址
     */
    private String macAddress;

    /**
     * 主机名字
     */
    private String hostName;

    /**
     * 事件id
     */
    private Integer eventId;

    /**
     * 风险等级
     */
    private Integer riskLevel;

    /**
     * 事件创建时间
     */
    private Date timestamp;

    /**
     * 执行日志分析的时间
     */
    private Date time;


    /**
     * 风险描述
     */
    private String riskDesc;

    /**
     * 日志类型（system/security）
     */
    private String channel;

    /**
     *
     */
    private Integer id;

    /**
     * 日志中 <EventData> 板块内容
     */
    private String eventData;

    /**
     * ai分析日志的结果
     */
    private String aiResult;

    /**
     *
     */
    public Long getLogId() {
        return logId;
    }

    /**
     *
     */
    public void setLogId(Long logId) {
        this.logId = logId;
    }

    /**
     * MAC地址
     */
    public String getMacAddress() {
        return macAddress;
    }

    /**
     * MAC地址
     */
    public void setMacAddress(String macAddress) {
        this.macAddress = macAddress;
    }

    /**
     * 主机名字
     */
    public String getHostName() {
        return hostName;
    }

    /**
     * 主机名字
     */
    public void setHostName(String hostName) {
        this.hostName = hostName;
    }

    /**
     * 事件id
     */
    public Integer getEventId() {
        return eventId;
    }

    /**
     * 事件id
     */
    public void setEventId(Integer eventId) {
        this.eventId = eventId;
    }

    /**
     * 风险等级
     */
    public Integer getRiskLevel() {
        return riskLevel;
    }

    /**
     * 风险等级
     */
    public void setRiskLevel(Integer riskLevel) {
        this.riskLevel = riskLevel;
    }

    /**
     * 事件创建时间
     */
    public Date getTimestamp() {
        return timestamp;
    }

    /**
     * 事件创建时间
     */
    public void setTimestamp(Date timestamp) {
        this.timestamp = timestamp;
    }

    /**
     * 风险描述
     */
    public String getRiskDesc() {
        return riskDesc;
    }

    /**
     * 风险描述
     */
    public void setRiskDesc(String riskDesc) {
        this.riskDesc = riskDesc;
    }

    /**
     * 日志类型（system/security）
     */
    public String getChannel() {
        return channel;
    }

    /**
     * 日志类型（system/security）
     */
    public void setChannel(String channel) {
        this.channel = channel;
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
     * 日志中 <EventData> 板块内容
     */
    public String getEventData() {
        return eventData;
    }

    /**
     * 日志中 <EventData> 板块内容
     */
    public void setEventData(String eventData) {
        this.eventData = eventData;
    }

    /**
     * ai分析日志的结果
     */
    public String getAiResult() {
        return aiResult;
    }

    /**
     * ai分析日志的结果
     */
    public void setAiResult(String aiResult) {
        this.aiResult = aiResult;
    }

    public Date getTime() {return time;}

    public void setTime(Date time) {this.time = time;}

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
        Log other = (Log) that;
        return (this.getLogId() == null ? other.getLogId() == null : this.getLogId().equals(other.getLogId()))
            && (this.getMacAddress() == null ? other.getMacAddress() == null : this.getMacAddress().equals(other.getMacAddress()))
            && (this.getHostName() == null ? other.getHostName() == null : this.getHostName().equals(other.getHostName()))
            && (this.getEventId() == null ? other.getEventId() == null : this.getEventId().equals(other.getEventId()))
            && (this.getRiskLevel() == null ? other.getRiskLevel() == null : this.getRiskLevel().equals(other.getRiskLevel()))
            && (this.getTimestamp() == null ? other.getTimestamp() == null : this.getTimestamp().equals(other.getTimestamp()))
            && (this.getRiskDesc() == null ? other.getRiskDesc() == null : this.getRiskDesc().equals(other.getRiskDesc()))
            && (this.getChannel() == null ? other.getChannel() == null : this.getChannel().equals(other.getChannel()))
            && (this.getId() == null ? other.getId() == null : this.getId().equals(other.getId()))
            && (this.getEventData() == null ? other.getEventData() == null : this.getEventData().equals(other.getEventData()))
            && (this.getAiResult() == null ? other.getAiResult() == null : this.getAiResult().equals(other.getAiResult()))
                && (this.getTime() == null ? other.getTime() == null : this.getTime().equals(other.getTime()));
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((getLogId() == null) ? 0 : getLogId().hashCode());
        result = prime * result + ((getMacAddress() == null) ? 0 : getMacAddress().hashCode());
        result = prime * result + ((getHostName() == null) ? 0 : getHostName().hashCode());
        result = prime * result + ((getEventId() == null) ? 0 : getEventId().hashCode());
        result = prime * result + ((getRiskLevel() == null) ? 0 : getRiskLevel().hashCode());
        result = prime * result + ((getTimestamp() == null) ? 0 : getTimestamp().hashCode());
        result = prime * result + ((getRiskDesc() == null) ? 0 : getRiskDesc().hashCode());
        result = prime * result + ((getChannel() == null) ? 0 : getChannel().hashCode());
        result = prime * result + ((getId() == null) ? 0 : getId().hashCode());
        result = prime * result + ((getEventData() == null) ? 0 : getEventData().hashCode());
        result = prime * result + ((getAiResult() == null) ? 0 : getAiResult().hashCode());
        result = prime * result + ((getTime() == null) ? 0 : getTime().hashCode());
        return result;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(getClass().getSimpleName());
        sb.append(" [");
        sb.append("Hash = ").append(hashCode());
        sb.append(", logId=").append(logId);
        sb.append(", macAddress=").append(macAddress);
        sb.append(", hostName=").append(hostName);
        sb.append(", eventId=").append(eventId);
        sb.append(", riskLevel=").append(riskLevel);
        sb.append(", timestamp=").append(timestamp);
        sb.append(", riskDesc=").append(riskDesc);
        sb.append(", channel=").append(channel);
        sb.append(", id=").append(id);
        sb.append(", eventData=").append(eventData);
        sb.append(", aiResult=").append(aiResult);
        sb.append(", time=").append(time);
        sb.append("]");
        return sb.toString();
    }


}
