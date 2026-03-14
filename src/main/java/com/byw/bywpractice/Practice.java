package com.byw.bywpractice;

import freemarker.template.Template;

import java.io.StringReader;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author fanyujie
 * @date 2026年03月14日 14:31
 * @return
 */
public class Practice {
    public static void main(String[] args) throws Exception {
        Map<String, Object> data = new HashMap(60);
        data.put("user", "edwin van");
        data.put("url", "www.example.com");
        data.put("status", "vip");
        data.put("date", "2026-03-14");
        String templateContent = "用户：${user?upper_case}，URL：${url}，状态：${(status!'NORMAL')?upper_case}";
        StringReader reader = new StringReader(templateContent);
        Template template = new Template("inlineTemplate", reader, null);
        StringWriter writer = new StringWriter();
        template.process(data, writer);
        System.out.println(writer.toString());
    }
}
