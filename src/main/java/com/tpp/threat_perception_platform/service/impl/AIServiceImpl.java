package com.tpp.threat_perception_platform.service.impl;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.JSONPObject;
import com.tpp.threat_perception_platform.service.AIService;
import org.springframework.stereotype.Service;

import java.io.OutputStream;
import  java.util.Scanner;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;

@Service
public class AIServiceImpl implements AIService {
    private final String ApiKey="sk-fbqkipctednqaduaxghzxwleetvbnxqoegzijtrmtuxcqmpy";
    private JSONObject defaultSettings=new JSONObject();

    public AIServiceImpl(){
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
        defaultSettings.put("messages",new JSONArray());
//        JSONObject responseFormat=new JSONObject();
//        responseFormat.put("type","json");
//        defaultSettings.put("response_format",responseFormat);
    }

    @Override
    public String aiAssistWithPrompt(String prompt, String data) {
        try {
            // 创建连接
            URL url = new URL("https://api.siliconflow.cn/v1/chat/completions");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Authorization", "Bearer sk-msqkwaaazrumwgtqqlolfkeupojnbherwlvxzsrwpabuaoep");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setDoOutput(true);

            // 构建 JSON 请求体
            JSONObject payload=defaultSettings.toJavaObject(JSONObject.class);

            JSONArray messages = (JSONArray) payload.get("messages");
            JSONObject message = new JSONObject();

            message.put("role", "system");
            message.put("content", prompt);
            messages.add(message);

            message = new JSONObject();
            message.put("role", "user");
            message.put("content", data);
            messages.add(message);

            payload.put("messages", messages);


            // 发送请求
            OutputStream os = conn.getOutputStream();
            os.write(payload.toJSONString().getBytes("UTF-8"));
            os.flush();
            os.close();

            // 读取响应
            Scanner scanner = new Scanner(conn.getInputStream(), "UTF-8");
            StringBuilder response = new StringBuilder();
            while (scanner.hasNextLine()) {
                response.append(scanner.nextLine());
            }
            scanner.close();

            JSONObject result = JSONObject.parseObject(response.toString());
            JSONArray choices = result.getJSONArray("choices");

            System.out.println("Total token cost: "+ JSONObject.parseObject(result.get("usage").toString()).get("total_tokens").toString());

            if (choices != null && choices.size() > 0) {
                return choices.getJSONObject(0).getJSONObject("message").getString("content");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
