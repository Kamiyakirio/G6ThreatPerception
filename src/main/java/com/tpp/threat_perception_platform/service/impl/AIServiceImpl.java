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
        defaultSettings.put("thinking_budget", 4096);
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

        JSONObject dataJsonObject= JSON.parseObject(data);

        try {

            if(dataJsonObject.containsKey("force")&&dataJsonObject.getInteger("force").equals(1)){
                throw new EmptyResultDataAccessException(1);
            }

            String result = jdbcTemplate.queryForObject(
                    "SELECT ai_result FROM ai_result_save WHERE data_shaed = ?",
                    String.class,
                    SHAUtil.hash(data, "SHA-256"));

            if (result != null && !result.trim().isEmpty()) {
                return result;
            }
        } catch (EmptyResultDataAccessException e) {
            // 查询无结果，忽略或处理
            try {
                // 创建连接
                URL url = new URL("https://api.siliconflow.cn/v1/chat/completions");
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("POST");
                conn.setRequestProperty("Authorization", "Bearer sk-1234567890abcdef");
                conn.setRequestProperty("Content-Type", "application/json");
                conn.setDoOutput(true);

                // 构建 JSON 请求体
                JSONObject payload = defaultSettings.toJavaObject(JSONObject.class);

                JSONArray messages = (JSONArray) payload.get("messages");
                JSONObject message = new JSONObject();

                message.put("role", "system");
                message.put("content", prompt);
                messages.add(message);

                dataJsonObject= JSON.parseObject(data);

                message = new JSONObject();
                message.put("role", "user");
                message.put("content", JSON.toJSONString(dataJsonObject.getJSONArray("data")));
                messages.add(message);

                payload.put("messages", messages);


                // 发送请求
                OutputStream os = conn.getOutputStream();
                os.write(payload.toJSONString().getBytes(StandardCharsets.UTF_8));
                os.flush();
                os.close();

                // 读取响应
                Scanner scanner = new Scanner(conn.getInputStream(), StandardCharsets.UTF_8);
                StringBuilder response = new StringBuilder();
                while (scanner.hasNextLine()) {
                    response.append(scanner.nextLine());
                }
                scanner.close();

                JSONObject result = JSONObject.parseObject(response.toString());
                JSONArray choices = result.getJSONArray("choices");

                System.out.println("Total token cost: " + JSONObject.parseObject(result.get("usage").toString()).get("total_tokens").toString());

                if (choices != null && choices.size() > 0) {
                    String AIResult = choices.getJSONObject(0).getJSONObject("message").getString("content");
                    String sql = "INSERT INTO ai_result_save (data_shaed, ai_result) VALUES (?, ?)";
                    jdbcTemplate.update(sql, SHAUtil.hash(data, "SHA-256"), AIResult);
                    return AIResult;
                }

            } catch (Exception ee) {
                ee.printStackTrace();
            }
            return null;
        }
        return null;
    }
}
