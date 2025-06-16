package com.tpp.threat_perception_platform.param;

public class SystemDetectParam {
    private String macAddress;

    private String hostId;

    private String type="system";

    private String hostName;



    public SystemDetectParam(String type, String hostName, String macAddress) {
        this.type = type;
        this.hostName = hostName;
        this.macAddress = macAddress;
    }

    public void setHostId(String hostId) {
        this.hostId = hostId;
    }

    public String getHostId() {
        return hostId;
    }

    public String getMacAddress() {
        return macAddress;
    }

    public String getType() {
        return type;
    }

    public String getHostName() {
        return hostName;
    }

    public void setMacAddress(String macAddress) {
        this.macAddress = macAddress;
    }

    public void setType(String type) {
        this.type = type;
    }

    public void setHostName(String hostName) {
        this.hostName = hostName;
    }
}
