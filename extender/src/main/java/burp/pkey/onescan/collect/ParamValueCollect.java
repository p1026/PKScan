package burp.pkey.onescan.collect;

import burp.pkey.common.utils.JsonUtils;
import burp.pkey.common.utils.StringUtils;
import burp.pkey.onescan.bean.CollectReqResp;
import burp.pkey.onescan.common.Constants;
import burp.pkey.onescan.manager.CollectManager;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;

/**
 * 收集各类参数键值对（JSON字段键值对、GET参数键值对、POST表单参数键值对）
 */
public class ParamValueCollect implements CollectManager.ICollectModule {

    @Override
    public String getName() {
        return "ParamValue";
    }

    @Override
    public List<String> doCollect(CollectReqResp reqResp) {
        Set<String> keyValueSet = new HashSet<>();

        // 收集JSON中的键值对（请求和响应都可能包含JSON）
        collectJsonKeyValuePairs(reqResp, keyValueSet);

        // 只处理请求中的参数键值对（GET和POST）
        if (reqResp.isRequest()) {
            // 收集GET参数键值对
            collectUrlParamKeyValuePairs(reqResp, keyValueSet);
            // 收集POST表单参数键值对
            collectPostParamKeyValuePairs(reqResp, keyValueSet);
        }

        return keyValueSet.isEmpty() ? null : new ArrayList<>(keyValueSet);
    }

    /**
     * 收集JSON中的所有键值对（格式：key=value）
     */
    private void collectJsonKeyValuePairs(CollectReqResp reqResp, Set<String> keyValueSet) {
        String body = reqResp.getBody();
        if (StringUtils.isEmpty(body)) {
            return;
        }
        if (JsonUtils.hasJson(body)) {
            try {
                // 使用Gson解析JSON元素
                JsonElement jsonElement = JsonParser.parseString(body);
                collectJsonElementKeyValuePairs(jsonElement, "", keyValueSet);
            } catch (Exception e) {
                // 忽略JSON解析异常
            }
        }
    }

    /**
     * 递归收集JSON元素中的所有键值对
     * 对于嵌套结构使用"父键.子键"的形式表示键名
     */
    private void collectJsonElementKeyValuePairs(JsonElement element, String parentKey, Set<String> keyValueSet) {
        if (element == null || element.isJsonNull()) {
            return;
        }
        if (element.isJsonObject()) {
            // 处理JSON对象
            JsonObject jsonObject = element.getAsJsonObject();
            for (Map.Entry<String, JsonElement> entry : jsonObject.entrySet()) {
                String currentKey = StringUtils.isEmpty(parentKey) ? entry.getKey() : parentKey + "." + entry.getKey();
                collectJsonElementKeyValuePairs(entry.getValue(), currentKey, keyValueSet);
            }
        } else if (element.isJsonArray()) {
            // 处理JSON数组（数组元素不记录键名，只记录值，或使用索引作为键名一部分）
            JsonArray jsonArray = element.getAsJsonArray();
            for (int i = 0; i < jsonArray.size(); i++) {
                String currentKey = StringUtils.isEmpty(parentKey) ? "[" + i + "]" : parentKey + "[" + i + "]";
                collectJsonElementKeyValuePairs(jsonArray.get(i), currentKey, keyValueSet);
            }
        } else if (element.isJsonPrimitive() && !StringUtils.isEmpty(parentKey)) {
            // 处理基本类型值（确保有对应的键名）
            String valueStr = element.getAsString();
            if (!StringUtils.isEmpty(valueStr)) {
                keyValueSet.add(parentKey + "=" + valueStr);
            }
        }
    }

    /**
     * 收集URL中的GET参数键值对（格式：key=value）
     */
    private void collectUrlParamKeyValuePairs(CollectReqResp reqResp, Set<String> keyValueSet) {
        String path = parsePath(reqResp);
        if (path == null) {
            return;
        }

        int queryIndex = path.indexOf("?");
        if (queryIndex == -1 || queryIndex >= path.length() - 1) {
            return;
        }

        String queryString = path.substring(queryIndex + 1);
        if (StringUtils.isEmpty(queryString)) {
            return;
        }

        String[] params = queryString.split("&");
        for (String param : params) {
            if (param.isEmpty()) {
                continue;
            }
            int eqIndex = param.indexOf("=");
            // 处理有值的参数（如a=123），无值参数不记录（如a&b=）
            if (eqIndex > 0 && eqIndex < param.length() - 1) {
                String paramName = param.substring(0, eqIndex);
                String paramValue = param.substring(eqIndex + 1);
                if (!StringUtils.isEmpty(paramName) && !StringUtils.isEmpty(paramValue)) {
                    keyValueSet.add(paramName + "=" + paramValue);
                }
            }
        }
    }

    /**
     * 解析请求路径（从请求行中提取）
     */
    private String parsePath(CollectReqResp reqResp) {
        String header = reqResp.getHeader();
        int offset = header.indexOf("\r\n");
        if (offset <= 0) {
            return null;
        }
        String reqLine = header.substring(0, offset);
        Matcher matcher = Constants.REGEX_REQ_LINE_URL.matcher(reqLine);
        if (!matcher.find()) {
            return null;
        }
        int start = matcher.start(1);
        int end = matcher.end(1);
        return reqLine.substring(start, end);
    }

    /**
     * 收集POST表单参数键值对（格式：key=value）
     */
    private void collectPostParamKeyValuePairs(CollectReqResp reqResp, Set<String> keyValueSet) {
        String contentType = getContentType(reqResp.getHeader());
        if (contentType == null || !contentType.contains("application/x-www-form-urlencoded")) {
            return;
        }

        String body = reqResp.getBody();
        if (StringUtils.isEmpty(body)) {
            return;
        }

        String[] params = body.split("&");
        for (String param : params) {
            if (param.isEmpty()) {
                continue;
            }
            int eqIndex = param.indexOf("=");
            // 处理有值的参数（如a=123），无值参数不记录（如a&b=）
            if (eqIndex > 0 && eqIndex < param.length() - 1) {
                String paramName = param.substring(0, eqIndex);
                String paramValue = param.substring(eqIndex + 1);
                if (!StringUtils.isEmpty(paramName) && !StringUtils.isEmpty(paramValue)) {
                    keyValueSet.add(paramName + "=" + paramValue);
                }
            }
        }
    }

    /**
     * 从请求头中获取Content-Type
     */
    private String getContentType(String header) {
        if (StringUtils.isEmpty(header)) {
            return null;
        }

        String[] lines = header.split("\r\n");
        for (String line : lines) {
            if (line.trim().toLowerCase().startsWith("content-type:")) {
                return line.substring("content-type:".length()).trim();
            }
        }
        return null;
    }
}