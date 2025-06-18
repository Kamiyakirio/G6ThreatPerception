package com.tpp.threat_perception_platform.utils;

import org.springframework.core.io.ClassPathResource;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.stream.Collectors;

public class TextFileLoader {
    public static String loadTextFile(String path) {
        try {
            ClassPathResource resource = new ClassPathResource(path);  // e.g., "texts/help.txt"
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(resource.getInputStream(), StandardCharsets.UTF_8))) {
                return reader.lines().collect(Collectors.joining("\n"));
            }
        } catch (Exception e) {
            throw new RuntimeException("无法加载文本文件：" + path, e);
        }
    }
}
