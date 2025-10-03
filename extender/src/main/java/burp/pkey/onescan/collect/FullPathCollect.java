package burp.pkey.onescan.collect;

import burp.pkey.onescan.bean.CollectReqResp;
import burp.pkey.onescan.common.Constants;
import burp.pkey.onescan.manager.CollectManager;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;

/**
 * 收集完整路径（包含所有目录层级，排除单个/）
 */
public class FullPathCollect implements CollectManager.ICollectModule {

    @Override
    public String getName() {
        return "FullPath";
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

        // 处理路径获取最终收集的目录
        String fullPath = processPath(path);
        // 排除单个/的情况
        if (fullPath != null && !fullPath.isEmpty() && !"/".equals(fullPath)) {
            List<String> result = new ArrayList<>();
            result.add(fullPath);
            return result;
        }

        return Collections.emptyList();
    }

    private String parsePath(CollectReqResp reqResp) {
        // 从请求头中解析路径
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

    private String processPath(String urlPath) {
        // 处理末尾斜杠情况（本身就是目录）
        if (urlPath.endsWith("/")) {
            return urlPath;
        }

        // 找到最后一个斜杠位置
        int lastSlashIndex = urlPath.lastIndexOf("/");
        // 如果没有斜杠，返回空（表示根路径下的文件）
        if (lastSlashIndex == -1) {
            return "";
        }

        // 判断最后一段是否为文件（包含.且不是以.结尾）
        String lastSegment = urlPath.substring(lastSlashIndex + 1);
        if (lastSegment.contains(".") && !lastSegment.endsWith(".")) {
            // 是文件，返回到最后一个斜杠的路径（包含斜杠）
            String dirPath = urlPath.substring(0, lastSlashIndex + 1);
            // 排除单个/的目录路径
            return "/".equals(dirPath) ? "" : dirPath;
        } else {
            // 是目录，返回完整路径加斜杠
            String dirPath = urlPath + "/";
            // 排除单个/的目录路径
            return "/".equals(dirPath) ? "" : dirPath;
        }
    }
}