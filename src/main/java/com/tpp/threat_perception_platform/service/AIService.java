package com.tpp.threat_perception_platform.service;

public interface AIService {
    public String aiAssistWithPrompt(String prompt, String data);

    String aiAssistWithoutThinking(String prompt, String data);
}
