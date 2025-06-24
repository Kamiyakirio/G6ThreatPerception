package com.tpp.threat_perception_platform.pojo;

/**
 * 
 * @TableName privilege_rights
 */
public class PrivilegeRights {
    /**
     * 
     */
    private Integer privilegeRightsId;

    /**
     * 
     */
    private String seProfileSingleProcessPrivilege;

    /**
     * 
     */
    private String seRemoteShutdownPrivilege;

    /**
     * 
     */
    private String seShutdownPrivilege;

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
    public Integer getPrivilegeRightsId() {
        return privilegeRightsId;
    }

    /**
     * 
     */
    public void setPrivilegeRightsId(Integer privilegeRightsId) {
        this.privilegeRightsId = privilegeRightsId;
    }

    /**
     * 
     */
    public String getSeProfileSingleProcessPrivilege() {
        return seProfileSingleProcessPrivilege;
    }

    /**
     * 
     */
    public void setSeProfileSingleProcessPrivilege(String seProfileSingleProcessPrivilege) {
        this.seProfileSingleProcessPrivilege = seProfileSingleProcessPrivilege;
    }

    /**
     * 
     */
    public String getSeRemoteShutdownPrivilege() {
        return seRemoteShutdownPrivilege;
    }

    /**
     * 
     */
    public void setSeRemoteShutdownPrivilege(String seRemoteShutdownPrivilege) {
        this.seRemoteShutdownPrivilege = seRemoteShutdownPrivilege;
    }

    /**
     * 
     */
    public String getSeShutdownPrivilege() {
        return seShutdownPrivilege;
    }

    /**
     * 
     */
    public void setSeShutdownPrivilege(String seShutdownPrivilege) {
        this.seShutdownPrivilege = seShutdownPrivilege;
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
        PrivilegeRights other = (PrivilegeRights) that;
        return (this.getPrivilegeRightsId() == null ? other.getPrivilegeRightsId() == null : this.getPrivilegeRightsId().equals(other.getPrivilegeRightsId()))
            && (this.getSeProfileSingleProcessPrivilege() == null ? other.getSeProfileSingleProcessPrivilege() == null : this.getSeProfileSingleProcessPrivilege().equals(other.getSeProfileSingleProcessPrivilege()))
            && (this.getSeRemoteShutdownPrivilege() == null ? other.getSeRemoteShutdownPrivilege() == null : this.getSeRemoteShutdownPrivilege().equals(other.getSeRemoteShutdownPrivilege()))
            && (this.getSeShutdownPrivilege() == null ? other.getSeShutdownPrivilege() == null : this.getSeShutdownPrivilege().equals(other.getSeShutdownPrivilege()))
            && (this.getType() == null ? other.getType() == null : this.getType().equals(other.getType()))
            && (this.getMacAddress() == null ? other.getMacAddress() == null : this.getMacAddress().equals(other.getMacAddress()));
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((getPrivilegeRightsId() == null) ? 0 : getPrivilegeRightsId().hashCode());
        result = prime * result + ((getSeProfileSingleProcessPrivilege() == null) ? 0 : getSeProfileSingleProcessPrivilege().hashCode());
        result = prime * result + ((getSeRemoteShutdownPrivilege() == null) ? 0 : getSeRemoteShutdownPrivilege().hashCode());
        result = prime * result + ((getSeShutdownPrivilege() == null) ? 0 : getSeShutdownPrivilege().hashCode());
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
        sb.append(", privilegeRightsId=").append(privilegeRightsId);
        sb.append(", seProfileSingleProcessPrivilege=").append(seProfileSingleProcessPrivilege);
        sb.append(", seRemoteShutdownPrivilege=").append(seRemoteShutdownPrivilege);
        sb.append(", seShutdownPrivilege=").append(seShutdownPrivilege);
        sb.append(", type=").append(type);
        sb.append(", macAddress=").append(macAddress);
        sb.append("]");
        return sb.toString();
    }
}