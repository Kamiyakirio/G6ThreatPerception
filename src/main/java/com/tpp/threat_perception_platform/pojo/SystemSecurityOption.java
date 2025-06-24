package com.tpp.threat_perception_platform.pojo;

/**
 * 
 * @TableName system_security_option
 */
public class SystemSecurityOption {
    /**
     * 
     */
    private Integer systemSecurityOptionId;

    /**
     * 
     */
    private Integer noLmHash;

    /**
     * 
     */
    private Integer limitBlankPasswordUse;

    /**
     * 
     */
    private Integer restrictAnonymous;

    /**
     * 
     */
    private Integer dontDisplayLastUserName;

    /**
     * 
     */
    private Integer enablePlainTextPassword;

    /**
     * 
     */
    private Integer clearPageFileAtShutdown;

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
    public Integer getSystemSecurityOptionId() {
        return systemSecurityOptionId;
    }

    /**
     * 
     */
    public void setSystemSecurityOptionId(Integer systemSecurityOptionId) {
        this.systemSecurityOptionId = systemSecurityOptionId;
    }

    /**
     * 
     */
    public Integer getNoLmHash() {
        return noLmHash;
    }

    /**
     * 
     */
    public void setNoLmHash(Integer noLmHash) {
        this.noLmHash = noLmHash;
    }

    /**
     * 
     */
    public Integer getLimitBlankPasswordUse() {
        return limitBlankPasswordUse;
    }

    /**
     * 
     */
    public void setLimitBlankPasswordUse(Integer limitBlankPasswordUse) {
        this.limitBlankPasswordUse = limitBlankPasswordUse;
    }

    /**
     * 
     */
    public Integer getRestrictAnonymous() {
        return restrictAnonymous;
    }

    /**
     * 
     */
    public void setRestrictAnonymous(Integer restrictAnonymous) {
        this.restrictAnonymous = restrictAnonymous;
    }

    /**
     * 
     */
    public Integer getDontDisplayLastUserName() {
        return dontDisplayLastUserName;
    }

    /**
     * 
     */
    public void setDontDisplayLastUserName(Integer dontDisplayLastUserName) {
        this.dontDisplayLastUserName = dontDisplayLastUserName;
    }

    /**
     * 
     */
    public Integer getEnablePlainTextPassword() {
        return enablePlainTextPassword;
    }

    /**
     * 
     */
    public void setEnablePlainTextPassword(Integer enablePlainTextPassword) {
        this.enablePlainTextPassword = enablePlainTextPassword;
    }

    /**
     * 
     */
    public Integer getClearPageFileAtShutdown() {
        return clearPageFileAtShutdown;
    }

    /**
     * 
     */
    public void setClearPageFileAtShutdown(Integer clearPageFileAtShutdown) {
        this.clearPageFileAtShutdown = clearPageFileAtShutdown;
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
        SystemSecurityOption other = (SystemSecurityOption) that;
        return (this.getSystemSecurityOptionId() == null ? other.getSystemSecurityOptionId() == null : this.getSystemSecurityOptionId().equals(other.getSystemSecurityOptionId()))
            && (this.getNoLmHash() == null ? other.getNoLmHash() == null : this.getNoLmHash().equals(other.getNoLmHash()))
            && (this.getLimitBlankPasswordUse() == null ? other.getLimitBlankPasswordUse() == null : this.getLimitBlankPasswordUse().equals(other.getLimitBlankPasswordUse()))
            && (this.getRestrictAnonymous() == null ? other.getRestrictAnonymous() == null : this.getRestrictAnonymous().equals(other.getRestrictAnonymous()))
            && (this.getDontDisplayLastUserName() == null ? other.getDontDisplayLastUserName() == null : this.getDontDisplayLastUserName().equals(other.getDontDisplayLastUserName()))
            && (this.getEnablePlainTextPassword() == null ? other.getEnablePlainTextPassword() == null : this.getEnablePlainTextPassword().equals(other.getEnablePlainTextPassword()))
            && (this.getClearPageFileAtShutdown() == null ? other.getClearPageFileAtShutdown() == null : this.getClearPageFileAtShutdown().equals(other.getClearPageFileAtShutdown()))
            && (this.getType() == null ? other.getType() == null : this.getType().equals(other.getType()))
            && (this.getMacAddress() == null ? other.getMacAddress() == null : this.getMacAddress().equals(other.getMacAddress()));
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((getSystemSecurityOptionId() == null) ? 0 : getSystemSecurityOptionId().hashCode());
        result = prime * result + ((getNoLmHash() == null) ? 0 : getNoLmHash().hashCode());
        result = prime * result + ((getLimitBlankPasswordUse() == null) ? 0 : getLimitBlankPasswordUse().hashCode());
        result = prime * result + ((getRestrictAnonymous() == null) ? 0 : getRestrictAnonymous().hashCode());
        result = prime * result + ((getDontDisplayLastUserName() == null) ? 0 : getDontDisplayLastUserName().hashCode());
        result = prime * result + ((getEnablePlainTextPassword() == null) ? 0 : getEnablePlainTextPassword().hashCode());
        result = prime * result + ((getClearPageFileAtShutdown() == null) ? 0 : getClearPageFileAtShutdown().hashCode());
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
        sb.append(", systemSecurityOptionId=").append(systemSecurityOptionId);
        sb.append(", noLmHash=").append(noLmHash);
        sb.append(", limitBlankPasswordUse=").append(limitBlankPasswordUse);
        sb.append(", restrictAnonymous=").append(restrictAnonymous);
        sb.append(", dontDisplayLastUserName=").append(dontDisplayLastUserName);
        sb.append(", enablePlainTextPassword=").append(enablePlainTextPassword);
        sb.append(", clearPageFileAtShutdown=").append(clearPageFileAtShutdown);
        sb.append(", type=").append(type);
        sb.append(", macAddress=").append(macAddress);
        sb.append("]");
        return sb.toString();
    }
}