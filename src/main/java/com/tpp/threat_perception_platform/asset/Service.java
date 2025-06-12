package com.tpp.threat_perception_platform.asset;

import java.util.Date;

/**
 * 
 * @TableName service
 */
public class Service {
    /**
     * 用于表示服务的唯一id
     */
    private Long serviceId;

    /**
     * 服务使用的协议
     */
    private String protocol;

    /**
     * 使用的端口
     */
    private Integer port;

    /**
     * 服务状态
     */
    private String state;

    /**
     * 
     */
    private String name;

    /**
     * 
     */
    private String product;

    /**
     * 
     */
    private String version;

    /**
     * 
     */
    private String extrainfo;

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
     * 区分每次扫描
     */
    private Integer detectId;

    private Integer risk;
    private String riskDesc;

    public void setRisk(Integer risk) {this.risk = risk;}
    public Integer getRisk() {return risk;}
    public void setRiskDesc(String riskDesc) {this.riskDesc = riskDesc;}
    public String getRiskDesc() {return riskDesc;}



    /**
     * 用于表示服务的唯一id
     */
    public Long getServiceId() {
        return serviceId;
    }

    /**
     * 用于表示服务的唯一id
     */
    public void setServiceId(Long serviceId) {
        this.serviceId = serviceId;
    }

    /**
     * 服务使用的协议
     */
    public String getProtocol() {
        return protocol;
    }

    /**
     * 服务使用的协议
     */
    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    /**
     * 使用的端口
     */
    public Integer getPort() {
        return port;
    }

    /**
     * 使用的端口
     */
    public void setPort(Integer port) {
        this.port = port;
    }

    /**
     * 服务状态
     */
    public String getState() {
        return state;
    }

    /**
     * 服务状态
     */
    public void setState(String state) {
        this.state = state;
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
    public String getProduct() {
        return product;
    }

    /**
     * 
     */
    public void setProduct(String product) {
        this.product = product;
    }

    /**
     * 
     */
    public String getVersion() {
        return version;
    }

    /**
     * 
     */
    public void setVersion(String version) {
        this.version = version;
    }

    /**
     * 
     */
    public String getExtrainfo() {
        return extrainfo;
    }

    /**
     * 
     */
    public void setExtrainfo(String extrainfo) {
        this.extrainfo = extrainfo;
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
        Service other = (Service) that;
        return (this.getServiceId() == null ? other.getServiceId() == null : this.getServiceId().equals(other.getServiceId()))
            && (this.getProtocol() == null ? other.getProtocol() == null : this.getProtocol().equals(other.getProtocol()))
            && (this.getPort() == null ? other.getPort() == null : this.getPort().equals(other.getPort()))
            && (this.getState() == null ? other.getState() == null : this.getState().equals(other.getState()))
            && (this.getName() == null ? other.getName() == null : this.getName().equals(other.getName()))
            && (this.getProduct() == null ? other.getProduct() == null : this.getProduct().equals(other.getProduct()))
            && (this.getVersion() == null ? other.getVersion() == null : this.getVersion().equals(other.getVersion()))
            && (this.getExtrainfo() == null ? other.getExtrainfo() == null : this.getExtrainfo().equals(other.getExtrainfo()))
            && (this.getHostName() == null ? other.getHostName() == null : this.getHostName().equals(other.getHostName()))
            && (this.getId() == null ? other.getId() == null : this.getId().equals(other.getId()))
            && (this.getMacAddress() == null ? other.getMacAddress() == null : this.getMacAddress().equals(other.getMacAddress()))
            && (this.getTime() == null ? other.getTime() == null : this.getTime().equals(other.getTime()))
            && (this.getDetectId() == null ? other.getDetectId() == null : this.getDetectId().equals(other.getDetectId()));
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((getServiceId() == null) ? 0 : getServiceId().hashCode());
        result = prime * result + ((getProtocol() == null) ? 0 : getProtocol().hashCode());
        result = prime * result + ((getPort() == null) ? 0 : getPort().hashCode());
        result = prime * result + ((getState() == null) ? 0 : getState().hashCode());
        result = prime * result + ((getName() == null) ? 0 : getName().hashCode());
        result = prime * result + ((getProduct() == null) ? 0 : getProduct().hashCode());
        result = prime * result + ((getVersion() == null) ? 0 : getVersion().hashCode());
        result = prime * result + ((getExtrainfo() == null) ? 0 : getExtrainfo().hashCode());
        result = prime * result + ((getHostName() == null) ? 0 : getHostName().hashCode());
        result = prime * result + ((getId() == null) ? 0 : getId().hashCode());
        result = prime * result + ((getMacAddress() == null) ? 0 : getMacAddress().hashCode());
        result = prime * result + ((getTime() == null) ? 0 : getTime().hashCode());
        result = prime * result + ((getDetectId() == null) ? 0 : getDetectId().hashCode());
        return result;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(getClass().getSimpleName());
        sb.append(" [");
        sb.append("Hash = ").append(hashCode());
        sb.append(", serviceId=").append(serviceId);
        sb.append(", protocol=").append(protocol);
        sb.append(", port=").append(port);
        sb.append(", state=").append(state);
        sb.append(", name=").append(name);
        sb.append(", product=").append(product);
        sb.append(", version=").append(version);
        sb.append(", extrainfo=").append(extrainfo);
        sb.append(", hostName=").append(hostName);
        sb.append(", id=").append(id);
        sb.append(", macAddress=").append(macAddress);
        sb.append(", time=").append(time);
        sb.append(", detectId=").append(detectId);
        sb.append("]");
        return sb.toString();
    }
}