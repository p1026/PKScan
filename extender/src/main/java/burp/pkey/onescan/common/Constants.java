package burp.pkey.onescan.common;

import java.util.regex.Pattern;

/**
 * 常量
 */
public interface Constants {

    // 插件信息
    String PLUGIN_NAME = "PKScan";
    String PLUGIN_VERSION = "1.0";
    boolean DEBUG = false;

    // 插件启动显示的信息
    String BANNER = "#" +
            "#############################################\n" +
            "  " + PLUGIN_NAME + " v" + PLUGIN_VERSION + "\n" +
            "  Author:    PKEY\n" +
            "  Github: https://github.com/p1026\n" +
            "##############################################\n";

    // 插件卸载显示的信息
    String UNLOAD_BANNER = "\n" +
            "###########################################################################\n" +
            "  " + PLUGIN_NAME + " uninstallation completed, thank you for your attention and use." + "\n" +
            "###########################################################################\n";

    // 匹配请求行的 URL 位置
    Pattern REGEX_REQ_LINE_URL = Pattern.compile("[A-Z]+\\s+(.*?)\\s+HTTP/", Pattern.CASE_INSENSITIVE);
}
