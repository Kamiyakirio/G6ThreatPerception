package com.tpp.threat_perception_platform.pojo;

/**
 * 
 * @TableName system_access
 */
public class SystemAccess {
    /**
     * 
     */
    private Integer systemAccessId;

    /**
     * 系统账号策略配置-密码最短留存期 值小于默认即合格
     */
    private Integer minimumPasswordAge;

    /**
     * 系统账号策略配置-密码最长留存期 值小于默认即合格
     */
    private Integer maximumPasswordAge;

    /**
     * 系统账号策略配置-密码长度最小值 值大于默认即合格
     */
    private Integer minimumPasswordLength;

    /**
     * 系统账号策略配置-密码必须符合复杂性要求策略 布尔值1为合格
     */
    private Integer passwordComplexity;

    /**
     * 系统账号策略配置-强制密码历史个记住的密码 值大于默认即合格
     */
    private Integer passwordHistorySize;

    /**
     * 系统账号策略配置-账户登录失败锁定阈值次数 值小于默认即合格
     */
    private Integer lockoutBadCount;

    /**
     * 系统账号策略配置-下次登录必须更改密码 布尔值0为合格
     */
    private Integer requireLogonToChangePassword;

    /**
     * 系统账号策略配置-强制过期 布尔值0为合格
     */
    private Integer forceLogoffWhenHourExpire;

    /**
     * 系统账号策略配置-当前系统默认管理账号登陆名称策略
     */
    private String newAdministratorName;

    /**
     * 系统账号策略配置-当前系统默认来宾用户登陆名称策略
     */
    private String newGuestName;

    /**
     * 系统账号策略配置-指示是否使用可逆加密来存储密码
     */
    private Integer clearTextPassword;

    /**
     * 系统账号策略配置-启用时此设置允许匿名用户查询本地LSA策略 (0关闭)
     */
    private Integer lsaAnonymousNameLookup;

    /**
     * 系统账号策略配置-管理员账户停用与启用策略
     */
    private Integer enableAdminAccount;

    /**
     * 系统账号策略配置-来宾账户停用与启用策略
     */
    private Integer enableGuestAccount;

    /**
     * 区分是否为用户基线数据记录还是标准
     */
    private String type;

    /**
     * 
     */
    private String macAddress;

    /**
     * 
     */
    public Integer getSystemAccessId() {
        return systemAccessId;
    }

    /**
     * 
     */
    public void setSystemAccessId(Integer systemAccessId) {
        this.systemAccessId = systemAccessId;
    }

    /**
     * 系统账号策略配置-密码最短留存期 值小于默认即合格
     */
    public Integer getMinimumPasswordAge() {
        return minimumPasswordAge;
    }

    /**
     * 系统账号策略配置-密码最短留存期 值小于默认即合格
     */
    public void setMinimumPasswordAge(Integer minimumPasswordAge) {
        this.minimumPasswordAge = minimumPasswordAge;
    }

    /**
     * 系统账号策略配置-密码最长留存期 值小于默认即合格
     */
    public Integer getMaximumPasswordAge() {
        return maximumPasswordAge;
    }

    /**
     * 系统账号策略配置-密码最长留存期 值小于默认即合格
     */
    public void setMaximumPasswordAge(Integer maximumPasswordAge) {
        this.maximumPasswordAge = maximumPasswordAge;
    }

    /**
     * 系统账号策略配置-密码长度最小值 值大于默认即合格
     */
    public Integer getMinimumPasswordLength() {
        return minimumPasswordLength;
    }

    /**
     * 系统账号策略配置-密码长度最小值 值大于默认即合格
     */
    public void setMinimumPasswordLength(Integer minimumPasswordLength) {
        this.minimumPasswordLength = minimumPasswordLength;
    }

    /**
     * 系统账号策略配置-密码必须符合复杂性要求策略 布尔值1为合格
     */
    public Integer getPasswordComplexity() {
        return passwordComplexity;
    }

    /**
     * 系统账号策略配置-密码必须符合复杂性要求策略 布尔值1为合格
     */
    public void setPasswordComplexity(Integer passwordComplexity) {
        this.passwordComplexity = passwordComplexity;
    }

    /**
     * 系统账号策略配置-强制密码历史个记住的密码 值大于默认即合格
     */
    public Integer getPasswordHistorySize() {
        return passwordHistorySize;
    }

    /**
     * 系统账号策略配置-强制密码历史个记住的密码 值大于默认即合格
     */
    public void setPasswordHistorySize(Integer passwordHistorySize) {
        this.passwordHistorySize = passwordHistorySize;
    }

    /**
     * 系统账号策略配置-账户登录失败锁定阈值次数 值小于默认即合格
     */
    public Integer getLockoutBadCount() {
        return lockoutBadCount;
    }

    /**
     * 系统账号策略配置-账户登录失败锁定阈值次数 值小于默认即合格
     */
    public void setLockoutBadCount(Integer lockoutBadCount) {
        this.lockoutBadCount = lockoutBadCount;
    }

    /**
     * 系统账号策略配置-下次登录必须更改密码 布尔值0为合格
     */
    public Integer getRequireLogonToChangePassword() {
        return requireLogonToChangePassword;
    }

    /**
     * 系统账号策略配置-下次登录必须更改密码 布尔值0为合格
     */
    public void setRequireLogonToChangePassword(Integer requireLogonToChangePassword) {
        this.requireLogonToChangePassword = requireLogonToChangePassword;
    }

    /**
     * 系统账号策略配置-强制过期 布尔值0为合格
     */
    public Integer getForceLogoffWhenHourExpire() {
        return forceLogoffWhenHourExpire;
    }

    /**
     * 系统账号策略配置-强制过期 布尔值0为合格
     */
    public void setForceLogoffWhenHourExpire(Integer forceLogoffWhenHourExpire) {
        this.forceLogoffWhenHourExpire = forceLogoffWhenHourExpire;
    }

    /**
     * 系统账号策略配置-当前系统默认管理账号登陆名称策略
     */
    public String getNewAdministratorName() {
        return newAdministratorName;
    }

    /**
     * 系统账号策略配置-当前系统默认管理账号登陆名称策略
     */
    public void setNewAdministratorName(String newAdministratorName) {
        this.newAdministratorName = newAdministratorName;
    }

    /**
     * 系统账号策略配置-当前系统默认来宾用户登陆名称策略
     */
    public String getNewGuestName() {
        return newGuestName;
    }

    /**
     * 系统账号策略配置-当前系统默认来宾用户登陆名称策略
     */
    public void setNewGuestName(String newGuestName) {
        this.newGuestName = newGuestName;
    }

    /**
     * 系统账号策略配置-指示是否使用可逆加密来存储密码
     */
    public Integer getClearTextPassword() {
        return clearTextPassword;
    }

    /**
     * 系统账号策略配置-指示是否使用可逆加密来存储密码
     */
    public void setClearTextPassword(Integer clearTextPassword) {
        this.clearTextPassword = clearTextPassword;
    }

    /**
     * 系统账号策略配置-启用时此设置允许匿名用户查询本地LSA策略 (0关闭)
     */
    public Integer getLsaAnonymousNameLookup() {
        return lsaAnonymousNameLookup;
    }

    /**
     * 系统账号策略配置-启用时此设置允许匿名用户查询本地LSA策略 (0关闭)
     */
    public void setLsaAnonymousNameLookup(Integer lsaAnonymousNameLookup) {
        this.lsaAnonymousNameLookup = lsaAnonymousNameLookup;
    }

    /**
     * 系统账号策略配置-管理员账户停用与启用策略
     */
    public Integer getEnableAdminAccount() {
        return enableAdminAccount;
    }

    /**
     * 系统账号策略配置-管理员账户停用与启用策略
     */
    public void setEnableAdminAccount(Integer enableAdminAccount) {
        this.enableAdminAccount = enableAdminAccount;
    }

    /**
     * 系统账号策略配置-来宾账户停用与启用策略
     */
    public Integer getEnableGuestAccount() {
        return enableGuestAccount;
    }

    /**
     * 系统账号策略配置-来宾账户停用与启用策略
     */
    public void setEnableGuestAccount(Integer enableGuestAccount) {
        this.enableGuestAccount = enableGuestAccount;
    }

    /**
     * 区分是否为用户基线数据记录还是标准
     */
    public String getType() {
        return type;
    }

    /**
     * 区分是否为用户基线数据记录还是标准
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
        SystemAccess other = (SystemAccess) that;
        return (this.getSystemAccessId() == null ? other.getSystemAccessId() == null : this.getSystemAccessId().equals(other.getSystemAccessId()))
            && (this.getMinimumPasswordAge() == null ? other.getMinimumPasswordAge() == null : this.getMinimumPasswordAge().equals(other.getMinimumPasswordAge()))
            && (this.getMaximumPasswordAge() == null ? other.getMaximumPasswordAge() == null : this.getMaximumPasswordAge().equals(other.getMaximumPasswordAge()))
            && (this.getMinimumPasswordLength() == null ? other.getMinimumPasswordLength() == null : this.getMinimumPasswordLength().equals(other.getMinimumPasswordLength()))
            && (this.getPasswordComplexity() == null ? other.getPasswordComplexity() == null : this.getPasswordComplexity().equals(other.getPasswordComplexity()))
            && (this.getPasswordHistorySize() == null ? other.getPasswordHistorySize() == null : this.getPasswordHistorySize().equals(other.getPasswordHistorySize()))
            && (this.getLockoutBadCount() == null ? other.getLockoutBadCount() == null : this.getLockoutBadCount().equals(other.getLockoutBadCount()))
            && (this.getRequireLogonToChangePassword() == null ? other.getRequireLogonToChangePassword() == null : this.getRequireLogonToChangePassword().equals(other.getRequireLogonToChangePassword()))
            && (this.getForceLogoffWhenHourExpire() == null ? other.getForceLogoffWhenHourExpire() == null : this.getForceLogoffWhenHourExpire().equals(other.getForceLogoffWhenHourExpire()))
            && (this.getNewAdministratorName() == null ? other.getNewAdministratorName() == null : this.getNewAdministratorName().equals(other.getNewAdministratorName()))
            && (this.getNewGuestName() == null ? other.getNewGuestName() == null : this.getNewGuestName().equals(other.getNewGuestName()))
            && (this.getClearTextPassword() == null ? other.getClearTextPassword() == null : this.getClearTextPassword().equals(other.getClearTextPassword()))
            && (this.getLsaAnonymousNameLookup() == null ? other.getLsaAnonymousNameLookup() == null : this.getLsaAnonymousNameLookup().equals(other.getLsaAnonymousNameLookup()))
            && (this.getEnableAdminAccount() == null ? other.getEnableAdminAccount() == null : this.getEnableAdminAccount().equals(other.getEnableAdminAccount()))
            && (this.getEnableGuestAccount() == null ? other.getEnableGuestAccount() == null : this.getEnableGuestAccount().equals(other.getEnableGuestAccount()))
            && (this.getType() == null ? other.getType() == null : this.getType().equals(other.getType()))
            && (this.getMacAddress() == null ? other.getMacAddress() == null : this.getMacAddress().equals(other.getMacAddress()));
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((getSystemAccessId() == null) ? 0 : getSystemAccessId().hashCode());
        result = prime * result + ((getMinimumPasswordAge() == null) ? 0 : getMinimumPasswordAge().hashCode());
        result = prime * result + ((getMaximumPasswordAge() == null) ? 0 : getMaximumPasswordAge().hashCode());
        result = prime * result + ((getMinimumPasswordLength() == null) ? 0 : getMinimumPasswordLength().hashCode());
        result = prime * result + ((getPasswordComplexity() == null) ? 0 : getPasswordComplexity().hashCode());
        result = prime * result + ((getPasswordHistorySize() == null) ? 0 : getPasswordHistorySize().hashCode());
        result = prime * result + ((getLockoutBadCount() == null) ? 0 : getLockoutBadCount().hashCode());
        result = prime * result + ((getRequireLogonToChangePassword() == null) ? 0 : getRequireLogonToChangePassword().hashCode());
        result = prime * result + ((getForceLogoffWhenHourExpire() == null) ? 0 : getForceLogoffWhenHourExpire().hashCode());
        result = prime * result + ((getNewAdministratorName() == null) ? 0 : getNewAdministratorName().hashCode());
        result = prime * result + ((getNewGuestName() == null) ? 0 : getNewGuestName().hashCode());
        result = prime * result + ((getClearTextPassword() == null) ? 0 : getClearTextPassword().hashCode());
        result = prime * result + ((getLsaAnonymousNameLookup() == null) ? 0 : getLsaAnonymousNameLookup().hashCode());
        result = prime * result + ((getEnableAdminAccount() == null) ? 0 : getEnableAdminAccount().hashCode());
        result = prime * result + ((getEnableGuestAccount() == null) ? 0 : getEnableGuestAccount().hashCode());
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
        sb.append(", systemAccessId=").append(systemAccessId);
        sb.append(", minimumPasswordAge=").append(minimumPasswordAge);
        sb.append(", maximumPasswordAge=").append(maximumPasswordAge);
        sb.append(", minimumPasswordLength=").append(minimumPasswordLength);
        sb.append(", passwordComplexity=").append(passwordComplexity);
        sb.append(", passwordHistorySize=").append(passwordHistorySize);
        sb.append(", lockoutBadCount=").append(lockoutBadCount);
        sb.append(", requireLogonToChangePassword=").append(requireLogonToChangePassword);
        sb.append(", forceLogoffWhenHourExpire=").append(forceLogoffWhenHourExpire);
        sb.append(", newAdministratorName=").append(newAdministratorName);
        sb.append(", newGuestName=").append(newGuestName);
        sb.append(", clearTextPassword=").append(clearTextPassword);
        sb.append(", lsaAnonymousNameLookup=").append(lsaAnonymousNameLookup);
        sb.append(", enableAdminAccount=").append(enableAdminAccount);
        sb.append(", enableGuestAccount=").append(enableGuestAccount);
        sb.append(", type=").append(type);
        sb.append(", macAddress=").append(macAddress);
        sb.append("]");
        return sb.toString();
    }
}