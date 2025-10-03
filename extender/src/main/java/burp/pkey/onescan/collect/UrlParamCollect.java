package burp.pkey.onescan.collect;

import burp.pkey.common.utils.StringUtils;
import burp.pkey.onescan.bean.CollectReqResp;
import burp.pkey.onescan.common.Constants;
import burp.pkey.onescan.manager.CollectManager;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;

public class UrlParamCollect implements CollectManager.ICollectModule {
    @Override
    public String getName() {
        return "UrlParam";
    }

    @Override
    public List<String> doCollect(CollectReqResp reqResp) {
        // 只处理请求数据
        if (!reqResp.isRequest()) {
            return null;
        }

        String path = parsePath(reqResp);
        if (path == null) {
            return null;
        }

        // 提取问号后的参数部分
        int queryIndex = path.indexOf("?");
        if (queryIndex == -1 || queryIndex >= path.length() - 1) {
            return null; // 没有参数或问号是最后一个字符
        }
        String queryString = path.substring(queryIndex + 1);
        if (StringUtils.isEmpty(queryString)) {
            return null;
        }

        // 分割参数并提取参数名
        List<String> paramNames = new ArrayList<>();
        String[] params = queryString.split("&");
        for (String param : params) {
            if (param.isEmpty()) {
                continue;
            }
            // 分割参数名和值（处理没有值的参数，如 ?a&b=1）
            int eqIndex = param.indexOf("=");
            String paramName = eqIndex > 0 ? param.substring(0, eqIndex) : param;
            if (!paramName.isEmpty()) {
                paramNames.add(paramName);
            }
        }

        return paramNames.isEmpty() ? null : paramNames;
    }

    private String parsePath(CollectReqResp reqResp) {
        // 从请求头中解析完整路径（包含参数部分）
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
}