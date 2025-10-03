package burp.pkey.onescan.collect;

import burp.pkey.common.utils.StringUtils;
import burp.pkey.onescan.bean.CollectReqResp;
import burp.pkey.onescan.manager.CollectManager;

import java.util.ArrayList;
import java.util.List;

/**
 * 收集 application/x-www-form-urlencoded 类型的 POST 参数名
 */
public class PostParamCollect implements CollectManager.ICollectModule {

    @Override
    public String getName() {
        return "PostParam";
    }

    @Override
    public List<String> doCollect(CollectReqResp reqResp) {
        // 只处理请求数据
        if (!reqResp.isRequest()) {
            return null;
        }

        // 检查 Content-Type 是否为 application/x-www-form-urlencoded
        String contentType = getContentType(reqResp.getHeader());
        if (contentType == null || !contentType.contains("application/x-www-form-urlencoded")) {
            return null;
        }

        // 获取请求体
        String body = reqResp.getBody();
        if (StringUtils.isEmpty(body)) {
            return null;
        }

        // 提取参数名
        List<String> paramNames = new ArrayList<>();
        String[] params = body.split("&");
        for (String param : params) {
            if (param.isEmpty()) {
                continue;
            }
            // 分割参数名和值（处理没有值的参数，如 a&b=1）
            int eqIndex = param.indexOf("=");
            String paramName = eqIndex > 0 ? param.substring(0, eqIndex) : param;
            if (!paramName.isEmpty()) {
                paramNames.add(paramName);
            }
        }

        return paramNames.isEmpty() ? null : paramNames;
    }

    /**
     * 从请求头中获取 Content-Type
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