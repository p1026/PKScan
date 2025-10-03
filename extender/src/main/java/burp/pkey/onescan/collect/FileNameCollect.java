package burp.pkey.onescan.collect;

import burp.pkey.onescan.bean.CollectReqResp;
import burp.pkey.onescan.manager.CollectManager;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class FileNameCollect implements CollectManager.ICollectModule {

    @Override
    public String getName() {
        return "FileName";
    }

    @Override
    public List<String> doCollect(CollectReqResp reqResp) {
        // 只处理请求数据
        if (!reqResp.isRequest()) {
            return Collections.emptyList();
        }

        // 解析路径
        String path = parsePath(reqResp);
        if (path == null || path.isEmpty()) {
            return Collections.emptyList();
        }

        // 提取文件名
        String fileName = extractFileName(path);
        if (fileName != null && !fileName.isEmpty()) {
            List<String> result = new ArrayList<>();
            result.add(fileName);
            return result;
        }

        return Collections.emptyList();
    }

    private String parsePath(CollectReqResp reqResp) {
        // 从请求头中解析路径（参考WebNameCollect的解析方式）
        String header = reqResp.getHeader();
        int offset = header.indexOf("\r\n");
        if (offset <= 0) {
            return null;
        }
        String reqLine = header.substring(0, offset);
        // 使用正则匹配URL路径部分（假设Constants中已有该正则）
        java.util.regex.Matcher matcher = burp.pkey.onescan.common.Constants.REGEX_REQ_LINE_URL.matcher(reqLine);
        if (!matcher.find()) {
            return null;
        }
        int start = matcher.start(1);
        int end = matcher.end(1);
        String path = reqLine.substring(start, end);

        // 移除参数和锚点部分
        if (path.contains("?")) {
            path = path.substring(0, path.indexOf("?"));
        }
        if (path.contains("#")) {
            path = path.substring(0, path.indexOf("#"));
        }

        return path;
    }

    private String extractFileName(String urlPath) {
        // 处理末尾斜杠情况
        if (urlPath.endsWith("/")) {
            return null;
        }

        // 找到最后一个斜杠位置
        int lastSlashIndex = urlPath.lastIndexOf("/");
        String lastSegment = (lastSlashIndex == -1) ? urlPath : urlPath.substring(lastSlashIndex + 1);

        // 检查是否包含.且不为空（排除仅含.的情况）
        if (!lastSegment.isEmpty() && lastSegment.contains(".") && !lastSegment.equals(".")) {
            return lastSegment;
        }

        return null;
    }
}