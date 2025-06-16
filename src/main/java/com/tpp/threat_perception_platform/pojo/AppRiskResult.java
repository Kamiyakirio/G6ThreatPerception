package com.tpp.threat_perception_platform.pojo;

import java.util.Date;

public class AppRiskResult {
    private Integer id;
    private String hostIdentifier;
    private String macAddress;
    private Integer appriskId;
    private String appriskName;
    private Byte isVulnerable;
    private String resultEvidence;
    private Date detectedAt;

    // Getters and Setters
    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getHostIdentifier() {
        return hostIdentifier;
    }

    public void setHostIdentifier(String hostIdentifier) {
        this.hostIdentifier = hostIdentifier;
    }

    public String getMacAddress() {
        return macAddress;
    }

    public void setMacAddress(String macAddress) {
        this.macAddress = macAddress;
    }

    public Integer getAppriskId() {
        return appriskId;
    }

    public void setAppriskId(Integer appriskId) {
        this.appriskId = appriskId;
    }

    public String getAppriskName() {
        return appriskName;
    }

    public void setAppriskName(String appriskName) {
        this.appriskName = appriskName;
    }

    public Byte getIsVulnerable() {
        return isVulnerable;
    }

    public void setIsVulnerable(Byte isVulnerable) {
        this.isVulnerable = isVulnerable;
    }

    public String getResultEvidence() {
        return resultEvidence;
    }

    public void setResultEvidence(String resultEvidence) {
        this.resultEvidence = resultEvidence;
    }

    public Date getDetectedAt() {
        return detectedAt;
    }

    public void setDetectedAt(Date detectedAt) {
        this.detectedAt = detectedAt;
    }

    @Override
    public String toString() {
        return "AppRiskResult{" +
               "id=" + id +
               ", hostIdentifier='" + hostIdentifier + '\'' +
               ", macAddress='" + macAddress + '\'' +
               ", appriskId=" + appriskId +
               ", appriskName='" + appriskName + '\'' +
               ", isVulnerable=" + isVulnerable +
               ", resultEvidence='" + resultEvidence + '\'' +
               ", detectedAt=" + detectedAt +
               '}';
    }
} 