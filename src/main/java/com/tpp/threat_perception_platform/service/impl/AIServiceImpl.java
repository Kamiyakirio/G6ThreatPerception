package com.tpp.threat_perception_platform.service.impl;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.tpp.threat_perception_platform.service.AIService;
import com.tpp.threat_perception_platform.utils.SHAUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;

@Service
public class AIServiceImpl implements AIService {
    private final JSONObject defaultSettings = new JSONObject();
    @Autowired
    private JdbcTemplate jdbcTemplate;

    public AIServiceImpl() {
        defaultSettings.put("model", "Qwen/Qwen3-14B");
        defaultSettings.put("stream", false);
        defaultSettings.put("max_tokens", 4096);
        defaultSettings.put("enable_thinking", true);
        defaultSettings.put("thinking_budget", 32768);
        defaultSettings.put("min_p", 0.05);
        defaultSettings.put("temperature", 0.7);
        defaultSettings.put("top_p", 0.7);
        defaultSettings.put("top_k", 50);
        defaultSettings.put("frequency_penalty", 0.5);
        defaultSettings.put("n", 1);
        defaultSettings.put("stop", new JSONArray());
        defaultSettings.put("messages", new JSONArray());
//        JSONObject responseFormat=new JSONObject();
//        responseFormat.put("type","json");
//        defaultSettings.put("response_format",responseFormat);
    }

    @Override
    public String aiAssistWithPrompt(String prompt, String data) {
        return aiAssist(prompt, data, true);
    }

    @Override
    public String aiAssistWithoutThinking(String prompt,String data) {
        return aiAssist(prompt, data, false);
    }

    private String aiAssist(String prompt, String data, boolean enableThinking) {
        JSONObject dataJsonObject = JSON.parseObject(data);
        boolean isForce = dataJsonObject.getInteger("force") != null && dataJsonObject.getInteger("force").equals(1);
        String dataHash = SHAUtil.hash(data + prompt, "SHA-256");

        if (!isForce) {
            try {
                String cachedResult = jdbcTemplate.queryForObject(
                        "SELECT ai_result FROM ai_result_save WHERE data_shaed = ?",
                        String.class,
                        dataHash
                );
                if (cachedResult != null && !cachedResult.trim().isEmpty()) {
                    return cachedResult;
                }
            } catch (EmptyResultDataAccessException ignore) {
                // 没有缓存，继续调用 AI
            }
        }

        try {
            String aiResult = callAIService(prompt, dataJsonObject, enableThinking);
            if (aiResult != null && !aiResult.trim().isEmpty()) {
                jdbcTemplate.update(
                        "INSERT INTO ai_result_save (data_shaed, ai_result) VALUES (?, ?)",
                        dataHash,
                        aiResult
                );
            }
            return aiResult;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private String callAIService(String prompt, JSONObject dataJsonObject, boolean enableThinking) throws Exception {
        URL url = new URL("https://api.siliconflow.cn/v1/chat/completions");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Authorization", "Bearer sk-");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);

        // 构建 JSON 请求体
        JSONObject payload = defaultSettings.toJavaObject(JSONObject.class);
        payload.put("enable_thinking", enableThinking);

        JSONArray messages = payload.getJSONArray("messages");
        if (messages == null) {
            messages = new JSONArray();
        }

        JSONObject systemMsg = new JSONObject();
        systemMsg.put("role", "system");
        systemMsg.put("content", prompt);
        messages.add(systemMsg);

        JSONObject userMsg = new JSONObject();
        userMsg.put("role", "user");
        userMsg.put("content", JSON.toJSONString(dataJsonObject.getJSONArray("data")));
        messages.add(userMsg);

        payload.put("messages", messages);

        // 发送请求
        try (OutputStream os = conn.getOutputStream()) {
            os.write(payload.toJSONString().getBytes(StandardCharsets.UTF_8));
            os.flush();
        }

        // 读取响应
        StringBuilder response = new StringBuilder();
        try (Scanner scanner = new Scanner(conn.getInputStream(), StandardCharsets.UTF_8)) {
            while (scanner.hasNextLine()) {
                response.append(scanner.nextLine());
            }
        }

        JSONObject result = JSON.parseObject(response.toString());
        JSONArray choices = result.getJSONArray("choices");

        System.out.println("Total token cost: " + result.getJSONObject("usage").get("total_tokens"));

        if (choices != null && !choices.isEmpty()) {
            return choices.getJSONObject(0).getJSONObject("message").getString("content");
        }

        return null;
    }
}
