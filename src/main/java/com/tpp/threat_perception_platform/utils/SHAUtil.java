package com.tpp.threat_perception_platform.utils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

public class SHAUtil {
    // 通用方法：支持 SHA-1、SHA-256、SHA-512 等
    public static String hash(String input, String algorithm) {
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm);
            byte[] hashBytes = md.digest(input.getBytes());
            // Java 17+ 推荐写法：也可以自己转16进制
            return HexFormat.of().formatHex(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("不支持的算法: " + algorithm, e);
        }
    }
}
