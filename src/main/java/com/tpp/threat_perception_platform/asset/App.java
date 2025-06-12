package com.tpp.threat_perception_platform.asset;

import java.util.Date;

/**
 * 
 * @TableName app
 */
public class App {
    /**
     * 应用ID作为主键
     */
    private Integer appId;

    /**
     * 应用名
     */
    private String displayName;

    /**
     * 安装位置
     */
    private String installLocation;

    /**
     * 卸载程序位置
     */
    private String uninstallString;

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
     * 应用ID作为主键
     */
    public Integer getAppId() {
        return appId;
    }

    /**
     * 应用ID作为主键
     */
    public void setAppId(Integer appId) {
        this.appId = appId;
    }

    /**
     * 应用名
     */
    public String getDisplayName() {
        return displayName;
    }

    /**
     * 应用名
     */
    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    /**
     * 安装位置
     */
    public String getInstallLocation() {
        return installLocation;
    }

    /**
     * 安装位置
     */
    public void setInstallLocation(String installLocation) {
        this.installLocation = installLocation;
    }

    /**
     * 卸载程序位置
     */
    public String getUninstallString() {
        return uninstallString;
    }

    /**
     * 卸载程序位置
     */
    public void setUninstallString(String uninstallString) {
        this.uninstallString = uninstallString;
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
        App other = (App) that;
        return (this.getAppId() == null ? other.getAppId() == null : this.getAppId().equals(other.getAppId()))
            && (this.getDisplayName() == null ? other.getDisplayName() == null : this.getDisplayName().equals(other.getDisplayName()))
            && (this.getInstallLocation() == null ? other.getInstallLocation() == null : this.getInstallLocation().equals(other.getInstallLocation()))
            && (this.getUninstallString() == null ? other.getUninstallString() == null : this.getUninstallString().equals(other.getUninstallString()))
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
        result = prime * result + ((getAppId() == null) ? 0 : getAppId().hashCode());
        result = prime * result + ((getDisplayName() == null) ? 0 : getDisplayName().hashCode());
        result = prime * result + ((getInstallLocation() == null) ? 0 : getInstallLocation().hashCode());
        result = prime * result + ((getUninstallString() == null) ? 0 : getUninstallString().hashCode());
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
        sb.append(", appId=").append(appId);
        sb.append(", displayName=").append(displayName);
        sb.append(", installLocation=").append(installLocation);
        sb.append(", uninstallString=").append(uninstallString);
        sb.append(", hostName=").append(hostName);
        sb.append(", id=").append(id);
        sb.append(", macAddress=").append(macAddress);
        sb.append(", time=").append(time);
        sb.append(", detectId=").append(detectId);
        sb.append("]");
        return sb.toString();
    }
}