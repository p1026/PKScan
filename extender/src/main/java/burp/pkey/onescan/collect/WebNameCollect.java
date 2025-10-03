package burp.pkey.onescan.collect;

import burp.pkey.onescan.bean.CollectReqResp;
import burp.pkey.onescan.common.Constants;
import burp.pkey.onescan.manager.CollectManager;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;

/**
 * Web 目录名收集
 * <p>
 * Created by vaycore on 2023-12-25.
 */
public class WebNameCollect implements CollectManager.ICollectModule {

    @Override
    public String getName() {
        return "WebName";
    }

    private static int fileCounter = 0;

//    @Override
//    public List<String> doCollect(CollectReqResp reqResp) {
//        // 只收集请求的数据
//        if (!reqResp.isRequest()) {
//            return null;
//        }
//        String path = parsePath(reqResp);
//        if (path == null || !path.startsWith("/")) {
//            return null;
//        }
//        // 根据斜杠数量，判断要不要处理
//        int countMatches = StringUtils.countMatches(path, "/");
//        if (countMatches <= 1) {
//            return null;
//        }
//        int endIndex = path.indexOf("/", 1);
//        // 可能存在双斜杠情况：'//'，所以 endIndex 需要大于 1 才行
//        if (endIndex <= 1) {
//            return null;
//        }
//        String webName = path.substring(1, endIndex);
//        // 检测空值
//        if (webName.trim().length() == 0) {
//            return null;
//        }
//        // 包装数据，返回
//        List<String> list = new ArrayList<>();
//        list.add(webName);
//        return list;
//    }

    @Override
    public List<String> doCollect(CollectReqResp reqResp) {
        // 只收集请求的数据
        if (!reqResp.isRequest()) {
            return null;
        }
        String path = parsePath(reqResp);
        if (path == null || !path.startsWith("/")) {
            return null;
        }
        // 处理路径并获取有效目录列表
        List<String> validDirs = getValidDirectories(path);
        return validDirs.isEmpty() ? null : validDirs;
    }

    private String parsePath(CollectReqResp reqResp) {
        // 解析请求行
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
        // 移除参数部分
        if (path.contains("?")) {
            path = path.substring(0, path.indexOf("?"));
        }
        // 移除锚点部分
        if (path.contains("#")) {
            path = path.substring(0, path.indexOf("#"));
        }
        return path;
    }

    /**
     * 从路径中提取有效的目录名（不包含/，且不包含.）
     */
    private List<String> getValidDirectories(String urlPath) {
        List<String> result = new ArrayList<>();

        // 处理文件后缀：如果包含.且不是最后一个字符，截取最后一个/之前的部分
        int lastSlashIndex = urlPath.lastIndexOf("/");
        if (lastSlashIndex > 0) {
            String lastSegment = urlPath.substring(lastSlashIndex + 1);
            // 如果最后一段包含.，则认为是文件，截取到最后一个/
            if (lastSegment.contains(".") && !lastSegment.endsWith(".")) {
                urlPath = urlPath.substring(0, lastSlashIndex + 1);
            }
        }

        // 分割路径（会自动忽略空字符串，因为连续//会产生空字符串）
        String[] segments = urlPath.split("/");

        for (String segment : segments) {
            // 跳过空字符串（处理开头/和连续//的情况）
            if (segment.isEmpty()) {
                continue;
            }
            // 跳过包含.的段（认为是文件或带扩展名的资源）
            if (segment.contains(".")) {
                continue;
            }
            // 添加有效的目录段
            result.add(segment);
        }

        return result;
    }

}
