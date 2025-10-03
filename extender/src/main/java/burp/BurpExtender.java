package burp;

import burp.pkey.common.helper.DomainHelper;
import burp.pkey.common.helper.QpsLimiter;
import burp.pkey.common.helper.UIHelper;
import burp.pkey.common.log.Logger;
import burp.pkey.common.utils.*;
import burp.pkey.onescan.OneScan;
import burp.pkey.onescan.bean.FpData;
import burp.pkey.onescan.bean.TaskData;
import burp.pkey.onescan.common.*;
import burp.pkey.onescan.info.OneScanInfoTab;
import burp.pkey.onescan.manager.CollectManager;
import burp.pkey.onescan.manager.FpManager;
import burp.pkey.onescan.manager.WordlistManager;
import burp.pkey.onescan.ui.tab.DataBoardTab;
import burp.pkey.onescan.ui.tab.FingerprintTab;
import burp.pkey.onescan.ui.tab.config.OtherTab;
import burp.pkey.onescan.ui.tab.config.RequestTab;
import burp.pkey.onescan.ui.widget.TaskTable;
import burp.pkey.onescan.ui.widget.payloadlist.PayloadItem;
import burp.pkey.onescan.ui.widget.payloadlist.PayloadRule;
import burp.pkey.onescan.ui.widget.payloadlist.ProcessingItem;

import javax.swing.*;
import javax.swing.Timer;
import java.awt.*;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.*;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.stream.Collectors;

import burp.pkey.common.utils.StringUtils;
import burp.pkey.common.utils.IPUtils;

/**
 * 插件入口
 * <p>
 * Created by vaycore on 2022-08-07.
 */
public class BurpExtender implements IBurpExtender, IProxyListener, IMessageEditorController,
        TaskTable.OnTaskTableEventListener, ITab, OnTabEventListener, IMessageEditorTabFactory,
        IExtensionStateListener, IContextMenuFactory {

    /**
     * 任务线程数量
     */
    private static final int TASK_THREAD_COUNT = 50;

    /**
     * 低频任务线程数量
     */
    private static final int LF_TASK_THREAD_COUNT = 25;

    /**
     * 指纹识别线程数量
     */
    private static final int FP_THREAD_COUNT = 10;

    /**
     * 空字节数组常量（防止频繁创建）
     */
    private static final byte[] EMPTY_BYTES = new byte[0];

    /**
     * 请求来源：代理
     */
    private static final String FROM_PROXY = "Proxy";

    /**
     * 请求来源：发送到 OneScan 扫描
     */
    private static final String FROM_SEND = "Send";

    /**
     * 请求来源：Payload Processing
     */
    private static final String FROM_PROCESS = "Process";

    /**
     * 请求来源：导入
     */
    private static final String FROM_IMPORT = "Import";

    /**
     * 请求来源：扫描
     */
    private static final String FROM_SCAN = "Scan";

    /**
     * 请求来源：重定向
     */
    private static final String FROM_REDIRECT = "Redirect";

    /**
     * 去重过滤集合
     */
    private final Set<String> sRepeatFilter = ConcurrentHashMap.newKeySet(500000);

    /**
     * 超时的请求主机集合
     */
    private final Set<String> sTimeoutReqHost = ConcurrentHashMap.newKeySet();

    private IBurpExtenderCallbacks mCallbacks;
    private IExtensionHelpers mHelpers;
    private OneScan mOneScan;
    private DataBoardTab mDataBoardTab;
    private IMessageEditor mRequestTextEditor;
    private IMessageEditor mResponseTextEditor;
    private ExecutorService mTaskThreadPool;
    private ExecutorService mLFTaskThreadPool;
    private ExecutorService mFpThreadPool;
    private ExecutorService mRefreshMsgTask;
    private IHttpRequestResponse mCurrentReqResp;
    private QpsLimiter mQpsLimit;
    private final AtomicInteger mTaskOverCounter = new AtomicInteger(0);
    private final AtomicInteger mTaskCommitCounter = new AtomicInteger(0);
    private final AtomicInteger mLFTaskOverCounter = new AtomicInteger(0);
    private final AtomicInteger mLFTaskCommitCounter = new AtomicInteger(0);
    private Timer mStatusRefresh;

    private static int fileCounter = 0;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        initData(callbacks);
        initView();
        initEvent();
        Logger.debug("register Extender ok! Log: %b", Constants.DEBUG);
    }

    private void initData(IBurpExtenderCallbacks callbacks) {
        this.mCallbacks = callbacks;
        this.mHelpers = callbacks.getHelpers();
        this.mTaskThreadPool = Executors.newFixedThreadPool(TASK_THREAD_COUNT);
        this.mLFTaskThreadPool = Executors.newFixedThreadPool(LF_TASK_THREAD_COUNT);
        this.mFpThreadPool = Executors.newFixedThreadPool(FP_THREAD_COUNT);
        this.mRefreshMsgTask = Executors.newSingleThreadExecutor();
        this.mCallbacks.setExtensionName(Constants.PLUGIN_NAME + " v" + Constants.PLUGIN_VERSION);
        // 初始化日志打印
        Logger.init(Constants.DEBUG, mCallbacks.getStdout(), mCallbacks.getStderr());
        // 初始化默认配置
        Config.init(callbacks);
        // 初始化域名辅助类
        DomainHelper.init("public_suffix_list.json");
        // 初始化QPS限制器
        initQpsLimiter();
        // 注册 OneScan 信息辅助面板
        this.mCallbacks.registerMessageEditorTabFactory(this);
        // 注册插件卸载监听器
        this.mCallbacks.registerExtensionStateListener(this);
    }

    /**
     * 获取工作目录路径（优先获取当前插件 jar 包所在目录配置文件，如果配置不存在，则使用默认工作目录）
     */
    private String getWorkDir() {
        String workDir = Paths.get(mCallbacks.getExtensionFilename())
                .getParent().toString() + File.separator + "PKScan" + File.separator;
        if (FileUtils.isDir(workDir)) {
            return workDir;
        }
        return null;
    }

    /**
     * 初始化 QPS 限制器
     */
    private void initQpsLimiter() {
        // 检测范围，如果不符合条件，不创建限制器
        int limit = Config.getInt(Config.KEY_QPS_LIMIT);
        int delay = Config.getInt(Config.KEY_REQUEST_DELAY);
        if (limit > 0 && limit <= 9999) {
            this.mQpsLimit = new QpsLimiter(limit, delay);
        }
    }

    private void initView() {
        mOneScan = new OneScan(mCallbacks);
//        mOneScan = new OneScan();
        mDataBoardTab = mOneScan.getDataBoardTab();
        // 注册事件
        mDataBoardTab.setOnTabEventListener(this);
        mOneScan.getConfigPanel().setOnTabEventListener(this);
        // 将页面添加到 BurpSuite
        mCallbacks.addSuiteTab(this);
        // 创建请求和响应控件
        mRequestTextEditor = mCallbacks.createMessageEditor(this, false);
        mResponseTextEditor = mCallbacks.createMessageEditor(this, false);
        mDataBoardTab.init(mRequestTextEditor.getComponent(), mResponseTextEditor.getComponent());
        mDataBoardTab.getTaskTable().setOnTaskTableEventListener(this);
    }

    private void initEvent() {
        // 监听代理的包
        mCallbacks.registerProxyListener(this);
        // 注册菜单
        mCallbacks.registerContextMenuFactory(this);
        // 状态栏刷新定时器
        mStatusRefresh = new Timer(1000, e -> {
            if (mDataBoardTab == null) {
                return;
            }
            mDataBoardTab.refreshTaskStatus(mTaskOverCounter.get(), mTaskCommitCounter.get());
            mDataBoardTab.refreshLFTaskStatus(mLFTaskOverCounter.get(), mLFTaskCommitCounter.get());
            mDataBoardTab.refreshTaskHistoryStatus();
            mDataBoardTab.refreshFpCacheStatus();
        });
        mStatusRefresh.start();
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        ArrayList<JMenuItem> items = new ArrayList<>();
        // 扫描选定目标
        JMenuItem sendToOneScanItem = new JMenuItem(L.get("send_to_plugin"));
        items.add(sendToOneScanItem);
        sendToOneScanItem.addActionListener((event) -> new Thread(() -> {
            IHttpRequestResponse[] messages = invocation.getSelectedMessages();
            for (IHttpRequestResponse httpReqResp : messages) {
                doScan(httpReqResp, FROM_SEND);
                // 线程池关闭后，停止发送扫描任务
                if (isTaskThreadPoolShutdown()) {
                    Logger.debug("sendToPlugin: thread pool is shutdown, stop sending scan task");
                    return;
                }
            }
        }).start());
        // 选择 Payload 扫描
        List<String> payloadList = WordlistManager.getItemList(WordlistManager.KEY_PAYLOAD);
        if (!payloadList.isEmpty() && payloadList.size() > 1) {
            JMenu menu = new JMenu(L.get("use_payload_scan"));
            items.add(menu);
            ActionListener listener = (event) -> new Thread(() -> {
                String action = event.getActionCommand();
                IHttpRequestResponse[] messages = invocation.getSelectedMessages();
                for (IHttpRequestResponse httpReqResp : messages) {
                    doScan(httpReqResp, FROM_SEND, action);
                    // 线程池关闭后，停止发送扫描任务
                    if (isTaskThreadPoolShutdown()) {
                        Logger.debug("usePayloadScan: thread pool is shutdown, stop sending scan task");
                        return;
                    }
                }
            }).start();
            for (String itemName : payloadList) {
                JMenuItem item = new JMenuItem(itemName);
                item.setActionCommand(itemName);
                item.addActionListener(listener);
                menu.add(item);
            }
        }
        return items;
    }

    @Override
    public String getTabCaption() {
        return Constants.PLUGIN_NAME;
    }

    @Override
    public Component getUiComponent() {
        return mOneScan;
    }

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        // 当请求和响应都有的时候，才进行下一步操作
        if (messageIsRequest) {
            return;
        }
        // 检测开关状态
        if (!mDataBoardTab.hasListenProxyMessage()) {
            return;
        }
        IHttpRequestResponse httpReqResp = message.getMessageInfo();
        // 扫描任务
        doScan(httpReqResp, FROM_PROXY);
    }

    /**
     * 将 pathDict 保存到文件以便调试
     * @param pathDict 要保存的路径字典
     * @param url 当前处理的URL，用于记录信息
     */
    private void savePathDictToFile(ArrayList<String> pathDict, String url) {
        try {
            // 创建 test 目录（如果不存在）
            File testDir = new File("test");
            if (!testDir.exists()) {
                testDir.mkdirs();
            }

            // 生成文件名
            String fileName = fileCounter + ".txt";
            File outputFile = new File(testDir, fileName);

            // 写入文件
            try (PrintWriter writer = new PrintWriter(new FileWriter(outputFile))) {
                writer.println("PathDict for URL: " + url);
                writer.println("Generated at: " + new Date());
                writer.println("====================================");

                for (int i = 0; i < pathDict.size(); i++) {
                    writer.println(i + ": " + pathDict.get(i));
                }

                writer.println("====================================");
                writer.println("Total items: " + pathDict.size());
            }

            Logger.debug("PathDict saved to: " + outputFile.getAbsolutePath());

            // 递增计数器
            fileCounter++;

        } catch (IOException e) {
            Logger.debug("Failed to save pathDict to file: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * 处理URL路径，去除末尾斜杠后分割为基础路径和最后一级目录
     * @param urlPath 输入的URL路径，例如 http://192.168.40.1:8000/aaa/
     * @return 长度为2的字符串数组，[0]为基础路径，[1]为最后一级目录；若处理失败返回null
     */
    private String[] splitUrlPath(String urlPath) {
        if (StringUtils.isEmpty(urlPath)) {
            return null;
        }

        // 去除末尾的斜杠
        String processedPath = urlPath;
        if (processedPath.endsWith("/")) {
            processedPath = processedPath.substring(0, processedPath.length() - 1);
        }

        // 找到最后一个斜杠的位置
        int lastSlashIndex = processedPath.lastIndexOf("/");
        if (lastSlashIndex == -1) {
            // 没有斜杠的情况（如纯域名）
            return new String[]{processedPath + "/", ""};
        }

        // 分割为基础路径和最后一级目录
        String basePath = processedPath.substring(0, lastSlashIndex + 1);
        String lastDir = processedPath.substring(lastSlashIndex + 1);

        return new String[]{basePath, lastDir};
    }

    /**
     * 过滤无效Host：仅保留IPv4地址和标准域名，其他格式全部过滤
     * @param host 待校验的Host（如"192.168.40.1"、"test.com"、"api.xxx.cn"）
     * @return true=Host格式有效（IPv4/域名）；false=无效格式（需过滤）
     */
    private boolean isValidHostForIpAndDomain(String host) {
        // 1. 过滤空Host（核心前提：无Host必为无效）
        if (StringUtils.isEmpty(host)) {
            Logger.debug("Invalid Host: Host is empty");
            return false;
        }

        // 2. 校验是否为合法IPv4地址（包含内网IP如192.168.40.1）
        // 依赖插件现有IPUtils工具类的hasIPv4方法（若不存在，可替换为下方注释的正则实现）
        if (IPUtils.hasIPv4(host)) {
            // 额外校验IPv4格式完整性（避免"192.168.40"这类不完整IP）
            String[] ipSegments = host.split("\\.");
            if (ipSegments.length == 4) {
                try {
                    // 校验每个段是否为0-255的数字
                    for (String segment : ipSegments) {
                        int num = Integer.parseInt(segment);
                        if (num < 0 || num > 255) {
                            throw new NumberFormatException();
                        }
                    }
                    Logger.debug("Valid Host (IPv4): " + host);
                    return true;
                } catch (NumberFormatException e) {
                    // 包含非数字段（如"192.168.40.a"），判定为无效
                    Logger.debug("Invalid Host (IPv4 format error): " + host);
                    return false;
                }
            } else {
                Logger.debug("Invalid Host (IPv4 segment count error): " + host);
                return false;
            }
        }

        // 3. 校验是否为合法域名（需满足：包含"."、无非法特殊字符、长度合规）
        // 域名合法规则：
        // - 必须包含"."（如"test.com"，排除"test"这类纯字母无点字符串）
        // - 仅允许字母、数字、"-"、"."（符合DNS域名规范，排除特殊字符如"/"、"?"、";"等）
        // - 首尾不能为"-"或"."（避免".test.com"、"test-.com"这类畸形域名）
        boolean isLegalDomain = true;
        // 3.1 必须包含"."
        if (!host.contains(".")) {
            isLegalDomain = false;
        }
        // 3.2 仅允许合法字符（字母、数字、"-"、"."）
        else if (!host.matches("^[a-zA-Z0-9.-]+$")) {
            isLegalDomain = false;
        }
        // 3.3 首尾不能为"-"或"."
        else if (host.startsWith("-") || host.startsWith(".") || host.endsWith("-") || host.endsWith(".")) {
            isLegalDomain = false;
        }
        // 3.4 域名长度限制（1-253字符，符合DNS规范）
        else if (host.length() < 1 || host.length() > 253) {
            isLegalDomain = false;
        }

        if (isLegalDomain) {
            Logger.debug("Valid Host (Domain): " + host);
            return true;
        } else {
            Logger.debug("Invalid Host (Domain format error): " + host);
            return false;
        }
    }

    private void doScan(IHttpRequestResponse httpReqResp, String from) {

        String item = WordlistManager.getItem(WordlistManager.KEY_PAYLOAD);
        List<String> payloads = WordlistManager.getPayload(item);
//        doScan(httpReqResp, from, item);
        doScan(httpReqResp, from, payloads);

        if (!mDataBoardTab.hasPayloadMultiBypass()){
            return;
        }

        List<String> bypass_payloads = new ArrayList<>();
        String bypass_first = "Bypass_First_List";
        List<String> bypass_first_payload = WordlistManager.getPayload(bypass_first);

        String bypass_end = "Bypass_End_List";
        List<String> bypass_end_payload = WordlistManager.getPayload(bypass_end);

        for (String urlPath : payloads) {

            String[] strings = splitUrlPath(urlPath);

            String old = null;
            if (strings != null) {
                old = strings[1];
            }

            for (String bypass : bypass_first_payload) {
                String newPath = null;
                if (strings != null) {
                    newPath = strings[0];
                }
                if (newPath != null && !bypass.startsWith("/") && !newPath.endsWith("/")) {
                    newPath = "/";
                }
                newPath += bypass + old;
                bypass_payloads.add(newPath);
            }

            for (String bypass : bypass_end_payload) {
                String newPath = null;
                if (strings != null) {
                    newPath = strings[0];
                }
                if (newPath != null && !bypass.startsWith("/") && !newPath.endsWith("/")) {
                    newPath = "/";
                }
                if (strings != null) {
                    newPath += strings[1] + bypass;
                }

                bypass_payloads.add(newPath);
            }
        }

        doScan(httpReqResp, from, bypass_payloads);

    }

    private void doScan(IHttpRequestResponse httpReqResp, String from, List<String> payloads) {
        if (httpReqResp == null || httpReqResp.getHttpService() == null) {
            return;
        }
        IRequestInfo info = mHelpers.analyzeRequest(httpReqResp);
        IHttpService service = httpReqResp.getHttpService();
        String host = service.getHost();

        // 新增：调用无效Host过滤函数，无效则直接终止任务
        if (!isValidHostForIpAndDomain(host)) {
            Logger.debug("Skip task: Invalid Host - " + host);
            return;
        }

        byte[] request = httpReqResp.getRequest();
        byte[] response = httpReqResp.getResponse();
        // 对来自代理的包进行检测，检测请求方法是否需要拦截
        if (from.equals(FROM_PROXY)) {
            String method = info.getMethod();
            if (includeMethodFilter(method)) {
                // 拦截不匹配的请求方法
                Logger.debug("doScan filter request method: %s, host: %s", method, host);
                return;
            }
            // 检测 Host 是否在白名单、黑名单中
            if (hostAllowlistFilter(host) || hostBlocklistFilter(host)) {
                Logger.debug("doScan allowlist and blocklist filter host: %s", host);
                return;
            }
            // 收集数据（只收集代理流量的数据）
            CollectManager.collect(true, host, request);
            CollectManager.collect(false, host, response);
        }
        // 如果启用，对来自重定向的包进行检测
        if (from.startsWith(FROM_REDIRECT) && Config.getBoolean(Config.KEY_REDIRECT_TARGET_HOST_LIMIT)) {
            // 检测 Host 是否在白名单、黑名单中
            if (hostAllowlistFilter(host) || hostBlocklistFilter(host)) {
                Logger.debug("doScan allowlist and blocklist filter host: %s", host);
                return;
            }
        }
        // 开启线程识别指纹，将识别结果缓存起来
        if (!mFpThreadPool.isShutdown()) {
            mFpThreadPool.execute(() -> FpManager.check(request, response));
        }
        // 准备生成任务
        URL url = getUrlByRequestInfo(info);

        // 原始请求也需要经过 Payload Process 处理（不过需要过滤一些后缀的流量）
        if (!proxyExcludeSuffixFilter(url.getPath())) {
            runScanTask(httpReqResp, info, null, from);
        }
        else {
            Logger.debug("proxyExcludeSuffixFilter filter request path: %s", url.getPath());
        }
        // 获取一下请求数据包中的请求路径
        String reqPath = getReqPathByRequestInfo(info);
        // 从请求路径中，尝试获取请求主机地址
        String reqHost = getReqHostByReqPath(reqPath);
        Logger.debug("doScan receive: %s", url.toString());

        ArrayList<String> pathDict = getUrlPathDict(url.getPath());

        // 检测是否禁用递归扫描
        if (!mDataBoardTab.hasDirScan()) {

            if (mDataBoardTab.hasPayloadMultiBypass()){
                String path = url.getPath();
                // 去除结尾的 '/' 符号
                if (path.endsWith("/")) {
                    path = path.substring(0, path.length() - 1);
                }

                // 拼接字典，发起请求
                for (String item : payloads) {
                    // 线程池关闭后，停止继续生成任务
                    if (isTaskThreadPoolShutdown()) {
                        return;
                    }
                    // 对完整 Host 地址的字典取消递归扫描（直接替换请求路径扫描）
                    if (StringUtils.isNotEmpty(path) && UrlUtils.isHTTP(item)) {
                        continue;
                    }
                    String urlPath = path + item;

                    // 如果配置的字典不含 '/' 前缀，在根目录下扫描时，自动添加 '/' 符号
                    if (StringUtils.isEmpty(path) && !item.startsWith("/") && !UrlUtils.isHTTP(item)) {
                        urlPath = "/" + item;
                    }
                    // 检测一下是否携带完整的 Host 地址（兼容一下携带了完整的 Host 地址的情况）
                    // 但有个前提：如果字典存在完整的 Host 地址，直接不做处理
                    if (UrlUtils.isHTTP(reqPath) && !UrlUtils.isHTTP(item)) {
                        urlPath = reqHost + urlPath;
                    }
                    runScanTask(httpReqResp, info, urlPath, FROM_SCAN);
                }
            }
            else if (mDataBoardTab.hasPayloadSingleBypass()){
                String bypass_first = "Bypass_First_List";
                List<String> bypass_first_payload = WordlistManager.getPayload(bypass_first);

                String bypass_end = "Bypass_End_List";
                List<String> bypass_end_payload = WordlistManager.getPayload(bypass_end);

                String urlPath = url.getPath();

                if (urlPath.contains("%") || urlPath.contains(".")) {
                    return;
                }

                String[] strings = splitUrlPath(urlPath);

                String end = null;
                if (strings != null) {
                    end = strings[1];
                }

                for (String item : bypass_first_payload) {

                    if (isTaskThreadPoolShutdown()) {
                        return;
                    }
                    String newUrlPath = null;
                    if (strings != null) {
                        newUrlPath = strings[0];
                    }
                    if (newUrlPath != null && !item.startsWith("/") && !newUrlPath.endsWith("/")) {
                        newUrlPath = "/";
                    }
                    newUrlPath += item + end;
                    runScanTask(httpReqResp, info, newUrlPath, FROM_SCAN);
                }

                for (String item : bypass_end_payload) {
                    if (isTaskThreadPoolShutdown()) {
                        return;
                    }
                    String newUrlPath = null;
                    if (strings != null) {
                        newUrlPath = strings[0] + strings[1] + item;
                    }
                    // 同样加入标识
                    runScanTask(httpReqResp, info, newUrlPath, FROM_SCAN);
                }
            }

            return;
        }

        // 一级目录一级目录递减访问
        for (int i = pathDict.size() - 1; i >= 0; i--) {
            String path = pathDict.get(i);
            // 去除结尾的 '/' 符号
            if (path.endsWith("/")) {
                path = path.substring(0, path.length() - 1);
            }

            // +++ 调用保存函数 +++
//            savePathDictToFile((ArrayList<String>) payloads, url);

            // 拼接字典，发起请求
            for (String item : payloads) {
                // 线程池关闭后，停止继续生成任务
                if (isTaskThreadPoolShutdown()) {
                    return;
                }
                // 对完整 Host 地址的字典取消递归扫描（直接替换请求路径扫描）
                if (StringUtils.isNotEmpty(path) && UrlUtils.isHTTP(item)) {
                    continue;
                }
                String urlPath = path + item;

                // 如果配置的字典不含 '/' 前缀，在根目录下扫描时，自动添加 '/' 符号
                if (StringUtils.isEmpty(path) && !item.startsWith("/") && !UrlUtils.isHTTP(item)) {
                    urlPath = "/" + item;
                }
                // 检测一下是否携带完整的 Host 地址（兼容一下携带了完整的 Host 地址的情况）
                // 但有个前提：如果字典存在完整的 Host 地址，直接不做处理
                if (UrlUtils.isHTTP(reqPath) && !UrlUtils.isHTTP(item)) {
                    urlPath = reqHost + urlPath;
                }
                runScanTask(httpReqResp, info, urlPath, FROM_SCAN);
            }
        }
    }

    private void doScan(IHttpRequestResponse httpReqResp, String from, String payloadItem) {
        if (httpReqResp == null || httpReqResp.getHttpService() == null) {
            return;
        }
        IRequestInfo info = mHelpers.analyzeRequest(httpReqResp);
        String host = httpReqResp.getHttpService().getHost();
        byte[] request = httpReqResp.getRequest();
        byte[] response = httpReqResp.getResponse();
        // 对来自代理的包进行检测，检测请求方法是否需要拦截
        if (from.equals(FROM_PROXY)) {
            String method = info.getMethod();
            if (includeMethodFilter(method)) {
                // 拦截不匹配的请求方法
                Logger.debug("doScan filter request method: %s, host: %s", method, host);
                return;
            }
            // 检测 Host 是否在白名单、黑名单中
            if (hostAllowlistFilter(host) || hostBlocklistFilter(host)) {
                Logger.debug("doScan allowlist and blocklist filter host: %s", host);
                return;
            }
            // 收集数据（只收集代理流量的数据）
            CollectManager.collect(true, host, request);
            CollectManager.collect(false, host, response);
        }
        // 如果启用，对来自重定向的包进行检测
        if (from.startsWith(FROM_REDIRECT) && Config.getBoolean(Config.KEY_REDIRECT_TARGET_HOST_LIMIT)) {
            // 检测 Host 是否在白名单、黑名单中
            if (hostAllowlistFilter(host) || hostBlocklistFilter(host)) {
                Logger.debug("doScan allowlist and blocklist filter host: %s", host);
                return;
            }
        }
        // 开启线程识别指纹，将识别结果缓存起来
        if (!mFpThreadPool.isShutdown()) {
            mFpThreadPool.execute(() -> FpManager.check(request, response));
        }
        // 准备生成任务
        URL url = getUrlByRequestInfo(info);
        // 原始请求也需要经过 Payload Process 处理（不过需要过滤一些后缀的流量）
        if (!proxyExcludeSuffixFilter(url.getPath())) {
            runScanTask(httpReqResp, info, null, from);
        } else {
            Logger.debug("proxyExcludeSuffixFilter filter request path: %s", url.getPath());
        }
        // 检测是否禁用递归扫描
        if (!mDataBoardTab.hasDirScan()) {
            return;
        }
        // 获取一下请求数据包中的请求路径
        String reqPath = getReqPathByRequestInfo(info);
        // 从请求路径中，尝试获取请求主机地址
        String reqHost = getReqHostByReqPath(reqPath);
        Logger.debug("doScan receive: %s", url.toString());
        ArrayList<String> pathDict = getUrlPathDict(url.getPath());
        List<String> payloads = WordlistManager.getPayload(payloadItem);

        // 一级目录一级目录递减访问
        for (int i = pathDict.size() - 1; i >= 0; i--) {
            String path = pathDict.get(i);
            // 去除结尾的 '/' 符号
            if (path.endsWith("/")) {
                path = path.substring(0, path.length() - 1);
            }

            // +++ 调用保存函数 +++
//            savePathDictToFile((ArrayList<String>) payloads, url);

            // 拼接字典，发起请求
            for (String item : payloads) {
                // 线程池关闭后，停止继续生成任务
                if (isTaskThreadPoolShutdown()) {
                    return;
                }
                // 对完整 Host 地址的字典取消递归扫描（直接替换请求路径扫描）
                if (StringUtils.isNotEmpty(path) && UrlUtils.isHTTP(item)) {
                    continue;
                }
                String urlPath = path + item;
                // 如果配置的字典不含 '/' 前缀，在根目录下扫描时，自动添加 '/' 符号
                if (StringUtils.isEmpty(path) && !item.startsWith("/") && !UrlUtils.isHTTP(item)) {
                    urlPath = "/" + item;
                }
                // 检测一下是否携带完整的 Host 地址（兼容一下携带了完整的 Host 地址的情况）
                // 但有个前提：如果字典存在完整的 Host 地址，直接不做处理
                if (UrlUtils.isHTTP(reqPath) && !UrlUtils.isHTTP(item)) {
                    urlPath = reqHost + urlPath;
                }
                runScanTask(httpReqResp, info, urlPath, FROM_SCAN);
            }
        }
    }

    /**
     * 从 IRequestInfo 实例中读取请求行中的请求路径
     *
     * @param info IRequestInfo 实例
     * @return 不存在返回空字符串
     */
    private String getReqPathByRequestInfo(IRequestInfo info) {
        if (info == null) {
            return "";
        }
        // 获取请求行
        List<String> headers = info.getHeaders();
        if (!headers.isEmpty()) {
            String reqLine = headers.get(0);
            Matcher matcher = Constants.REGEX_REQ_LINE_URL.matcher(reqLine);
            if (matcher.find() && matcher.groupCount() >= 1) {

                return matcher.group(1);

            }
        }
        return "";
    }

    /**
     * 从请求路径中（有些站点请求路径中包含完整的 Host 地址）获取请求的 Host 地址
     *
     * @param reqPath 请求路径
     * @return 不包含 Host 地址，返回空字符串
     */
    private String getReqHostByReqPath(String reqPath) {
        if (StringUtils.isEmpty(reqPath) || !UrlUtils.isHTTP(reqPath)) {
            return "";
        }
        try {
            URL url = new URL(reqPath);
            return UrlUtils.getReqHostByURL(url);
        } catch (MalformedURLException e) {
            return "";
        }
    }

    /**
     * 过滤请求方法
     *
     * @param method 请求方法
     * @return true=拦截；false=不拦截
     */
    private boolean includeMethodFilter(String method) {
        String includeMethod = Config.get(Config.KEY_INCLUDE_METHOD);
        // 如果配置为空，不拦截任何请求方法
        if (StringUtils.isNotEmpty(includeMethod)) {
            String[] split = includeMethod.split("\\|");
            boolean hasFilter = true;
            for (String item : split) {
                if (method.equals(item)) {
                    hasFilter = false;
                    break;
                }
            }
            return hasFilter;
        }
        return false;
    }

    /**
     * Host 白名单过滤
     *
     * @param host Host
     * @return true=拦截；false=不拦截
     */
    private boolean hostAllowlistFilter(String host) {
        List<String> list = WordlistManager.getHostAllowlist();
        // 白名单为空，不启用白名单
        if (list.isEmpty()) {
            return false;
        }
        for (String item : list) {
            if (matchHost(host, item)) {
                return false;
            }
        }
        Logger.debug("hostAllowlistFilter filter host: %s", host);
        return true;
    }

    /**
     * Host 黑名单过滤
     *
     * @param host Host
     * @return true=拦截；false=不拦截
     */
    private boolean hostBlocklistFilter(String host) {
        List<String> list = WordlistManager.getHostBlocklist();
        // 黑名单为空，不启用黑名单
        if (list.isEmpty()) {
            return false;
        }
        for (String item : list) {
            if (matchHost(host, item)) {
                Logger.debug("hostBlocklistFilter filter host: %s （rule: %s）", host, item);
                return true;
            }
        }
        return false;
    }

    /**
     * 检测 Host 是否匹配规则
     *
     * @param host Host（不包含协议、端口号）
     * @param rule 规则
     * @return true=匹配；false=不匹配
     */
    private static boolean matchHost(String host, String rule) {
        if (StringUtils.isEmpty(host)) {
            return StringUtils.isEmpty(rule);
        }
        // 规则就是*号，直接返回true
        if (rule.equals("*")) {
            return true;
        }
        // 不包含*号，检测 Host 与规则是否相等
        if (!rule.contains("*")) {
            return host.equals(rule);
        }
        // 根据*号位置，进行匹配
        String ruleValue = rule.replace("*", "");
        if (rule.startsWith("*") && rule.endsWith("*")) {
            return host.contains(ruleValue);
        } else if (rule.startsWith("*")) {
            return host.endsWith(ruleValue);
        } else if (rule.endsWith("*")) {
            return host.startsWith(ruleValue);
        } else {
            String[] split = rule.split("\\*");
            return host.startsWith(split[0]) && host.endsWith(split[1]);
        }
    }

    /**
     * 代理请求的后缀过滤
     *
     * @param reqPath 请求路径（不包含 Query 参数）
     * @return true=拦截；false=不拦截
     */
    private boolean proxyExcludeSuffixFilter(String reqPath) {
        if (StringUtils.isEmpty(reqPath) || "/".equals(reqPath)) {
            return false;
        }
        // 统一转换为小写
        String suffix = Config.get(Config.KEY_EXCLUDE_SUFFIX).toLowerCase();
        String path = reqPath.toLowerCase();
        if (StringUtils.isEmpty(suffix)) {
            return false;
        }
        // 配置中不存在多个过滤的后缀名，直接检测
        if (!suffix.contains("|") && path.endsWith("." + suffix)) {
            return true;
        }
        String[] split = suffix.split("\\|");
        for (String item : split) {
            if (path.endsWith("." + item)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 使用 '/' 分割 URL 实例的 path 数据，通过组合第一层级目录，生成字典列表
     *
     * @param urlPath URL 实例的 path 数据
     * @return 失败返回空列表
     */
    private ArrayList<String> getUrlPathDict(String urlPath) {
        String direct = Config.get(Config.KEY_SCAN_LEVEL_DIRECT);
        int scanLevel = Config.getInt(Config.KEY_SCAN_LEVEL);
        ArrayList<String> result = new ArrayList<>();
        result.add("/");
        if (StringUtils.isEmpty(urlPath) || "/".equals(urlPath)) {
            return result;
        }
        // 限制方向从左往右，并且扫描层级为1
        if (Config.DIRECT_LEFT.equals(direct) && scanLevel <= 1) {
            return result;
        }
        // 结尾如果不是'/'符号，去掉访问的文件
        if (!urlPath.endsWith("/")) {
            urlPath = urlPath.substring(0, urlPath.lastIndexOf("/") + 1);
        }

        String[] splitDirname = urlPath.split("/");

        if (splitDirname.length == 0) {
            return result;
        }
        // 限制方向从右往左，默认不扫描根目录
        if (Config.DIRECT_RIGHT.equals(direct) && scanLevel < splitDirname.length) {
            result.remove("/");
        }
        StringBuilder sb = new StringBuilder("/");
        for (String dirname : splitDirname) {
            if (StringUtils.isNotEmpty(dirname)) {
                sb.append(dirname).append("/");
                int level = StringUtils.countMatches(sb.toString(), "/");
                // 根据不同方向，限制目录层级
                if (Config.DIRECT_LEFT.equals(direct) && level > scanLevel) {
                    continue;
                } else if (Config.DIRECT_RIGHT.equals(direct)) {
                    level = splitDirname.length - level;
                    if (level >= scanLevel) {
                        continue;
                    }
                }

                result.add(sb.toString());
            }
        }
        return result;
    }

    /**
     * 运行扫描任务
     *
     * @param httpReqResp   请求响应实例
     * @param info          IRequestInfo 实例
     * @param pathWithQuery 路径+query参数
     * @param from          请求来源
     */
    private void runScanTask(IHttpRequestResponse httpReqResp, IRequestInfo info, String pathWithQuery, String from) {

        IHttpService service = httpReqResp.getHttpService();

        // 处理请求头
        byte[] request = handleHeader(httpReqResp, info, pathWithQuery, from);
        // 处理请求头失败时，丢弃该任务
        if (request == null) {
            return;
        }
        IRequestInfo newInfo = mHelpers.analyzeRequest(service, request);
        String reqId = generateReqId(newInfo, from);
        // 如果当前 URL 已经扫描，中止任务
        if (checkRepeatFilterByReqId(reqId)) {
            return;
        }
        // 如果未启用“请求包处理”功能，直接对扫描的任务发起请求
        if (!mDataBoardTab.hasPayloadProcessing()) {
            doBurpRequest(service, reqId, request, from);
            return;
        }

//        savePathDictToFile(new ArrayList<>(), pathWithQuery);

        // 运行已经启用并且需要合并的任务
        runEnableAndMergeTask(service, reqId, request, from);
        // 运行已经启用并且不需要合并的任务
        runEnabledWithoutMergeProcessingTask(service, reqId, request);
    }

    /**
     * 生成请求 ID
     *
     * @param info IRequestInfo 实例
     * @param from 请求来源
     * @return 失败返回 "null" 字符串
     */
    private String generateReqId(IRequestInfo info, String from) {
        if (info == null || StringUtils.isEmpty(from)) {
            return "null";
        }
        String reqPath = getReqPathByRequestInfo(info);
        // 生成携带完整的 Host 地址请求的请求 ID 值
        if (UrlUtils.isHTTP(reqPath)) {
            URL originUrl = info.getUrl();
            String originReqHost = UrlUtils.getReqHostByURL(originUrl);
            return originReqHost + "->" + reqPath;
        }
        URL url = getUrlByRequestInfo(info);
        String reqHost = UrlUtils.getReqHostByURL(url);
        String result = null;
        // 生成重定向请求的请求 ID 值
        if (from.startsWith(FROM_REDIRECT)) {
            return reqHost + reqPath;
        }
        // 默认使用 http://x.x.x.x/path/to/index.html 格式作为请求 ID 值
        return reqHost + url.getPath();
    }

    /**
     * 根据 Url 检测是否重复扫描
     *
     * @param reqId 请求 ID
     * @return true=重复；false=不重复
     */
    private synchronized boolean checkRepeatFilterByReqId(String reqId) {
        if (sRepeatFilter.contains(reqId)) {
            return true;
        }
        return !sRepeatFilter.add(reqId);
    }

    /**
     * 运行已经启用并且需要合并的任务
     *
     * @param service     请求目标服务实例
     * @param reqId       请求 ID
     * @param reqRawBytes 请求数据包
     * @param from        请求来源
     */
    private void runEnableAndMergeTask(IHttpService service, String reqId, byte[] reqRawBytes, String from) {
        // 获取已经启用并且需要合并的“请求包处理”规则
        List<ProcessingItem> processList = getPayloadProcess()
                .stream().filter(ProcessingItem::isEnabledAndMerge)
                .collect(Collectors.toList());
        // 如果规则为空，直接发起请求
        if (processList.isEmpty()) {
            doBurpRequest(service, reqId, reqRawBytes, from);
            return;
        }
        byte[] resultBytes = reqRawBytes;
        for (ProcessingItem item : processList) {
            ArrayList<PayloadItem> items = item.getItems();
            resultBytes = handlePayloadProcess(service, resultBytes, items);
        }
        if (resultBytes != null) {
            // 检测是否未进行任何处理
            boolean equals = Arrays.equals(reqRawBytes, resultBytes);
            // 未进行任何处理时，不变更 from 值
            String newFrom = equals ? from : from + "（" + FROM_PROCESS + "）";
            doBurpRequest(service, reqId, resultBytes, newFrom);
        } else {
            // 如果规则处理异常导致数据返回为空，则发送原来的请求
            doBurpRequest(service, reqId, reqRawBytes, from);
        }
    }

    /**
     * 运行已经启用并且不需要合并的任务
     *
     * @param service     请求目标服务实例
     * @param reqId       请求 ID
     * @param reqRawBytes 请求数据包
     */
    private void runEnabledWithoutMergeProcessingTask(IHttpService service, String reqId, byte[] reqRawBytes) {
        // 遍历规则列表，进行 Payload Processing 处理后，再次请求数据包
        getPayloadProcess().parallelStream().filter(ProcessingItem::isEnabledWithoutMerge)
                .forEach((item) -> {
                    ArrayList<PayloadItem> items = item.getItems();
                    byte[] requestBytes = handlePayloadProcess(service, reqRawBytes, items);
                    // 因为不需要合并的规则是将每条处理完成的数据包都发送请求，所以规则处理异常的请求包，不需要发送请求
                    if (requestBytes == null) {
                        return;
                    }
                    // 检测是否未进行任何处理（如上所述的原因，未进行任何处理的请求包，也不需要发送请求）
                    boolean equals = Arrays.equals(reqRawBytes, requestBytes);
                    if (equals) {
                        return;
                    }
                    doBurpRequest(service, reqId, requestBytes, FROM_PROCESS + "（" + item.getName() + "）");
                });
    }


    /**
     * 使用 Burp 自带的方式请求
     *
     * @param service     请求目标服务实例
     * @param reqId       请求 ID
     * @param reqRawBytes 请求数据包
     * @param from        请求来源
     */
    private void doBurpRequest(IHttpService service, String reqId, byte[] reqRawBytes, String from) {

        // 线程池关闭后，不接收任何任务
        if (isTaskThreadPoolShutdown()) {
            Logger.debug("doBurpRequest: thread pool is shutdown, intercept req id: %s", reqId);
            // 将未执行的任务从去重过滤集合中移除
            sRepeatFilter.remove(reqId);
            return;
        }
        // 创建任务运行实例
        TaskRunnable task = new TaskRunnable(reqId, from) {
            @Override
            public void run() {
                String reqId = getReqId();
                // 低频任务不进行 QPS 限制
                if (!isLowFrequencyTask(from) && checkQPSLimit()) {
                    // 拦截后，将未执行的任务从去重过滤集合中移除
                    sRepeatFilter.remove(reqId);
                    // 任务完成计数
                    incrementTaskOverCounter(from);
                    return;
                }
                Logger.debug("Do Send Request id: %s", reqId);
                // 获取配置的请求重试次数
                int retryCount = Config.getInt(Config.KEY_RETRY_COUNT);
                // 发起请求
                IHttpRequestResponse newReqResp = doMakeHttpRequest(service, reqRawBytes, retryCount);
                // 构建展示的数据包
                TaskData data = buildTaskData(newReqResp, from);
                mDataBoardTab.getTaskTable().addTaskData(data);
                // 收集数据
                CollectManager.collect(false, service.getHost(), newReqResp.getResponse());
                // 处理重定向
                handleFollowRedirect(data);
                // 任务完成计数
                incrementTaskOverCounter(from);
            }
        };
        // 将任务添加线程池
        try {
            // 如果是低频任务，使用低频的任务线程池
            if (isLowFrequencyTask(from)) {
                mLFTaskThreadPool.execute(task);
                // 低频任务提交计数
                mLFTaskCommitCounter.incrementAndGet();
            } else {
                // 否则使用常规的任务线程池
                mTaskThreadPool.execute(task);
                // 任务提交计数
                mTaskCommitCounter.incrementAndGet();
            }
        } catch (Exception e) {
            Logger.error("doBurpRequest thread execute error: %s", e.getMessage());
        }
    }

    /**
     * 任务线程池是否关闭
     *
     * @return true=是；false=否
     */
    private boolean isTaskThreadPoolShutdown() {
        return mTaskThreadPool.isShutdown() || mLFTaskThreadPool.isShutdown();
    }

    /**
     * 当前请求来源，是否为低频任务
     *
     * @param from 请求来源
     * @return true=是；false=否
     */
    private boolean isLowFrequencyTask(String from) {
        if (StringUtils.isEmpty(from)) {
            return false;
        }
        return from.startsWith(FROM_PROXY) || from.startsWith(FROM_SEND) || from.startsWith(FROM_REDIRECT);
    }

    /**
     * 增加任务完成计数
     *
     * @param from 请求来源
     */
    private void incrementTaskOverCounter(String from) {
        if (isLowFrequencyTask(from)) {
            // 低频任务完成计数
            mLFTaskOverCounter.incrementAndGet();
        } else {
            // 任务完成计数
            mTaskOverCounter.incrementAndGet();
        }
    }

    /**
     * 处理跟随重定向
     */
    private void handleFollowRedirect(TaskData data) {
        // 如果未启用“跟随重定向”功能，不继续执行
        if (!Config.getBoolean(Config.KEY_FOLLOW_REDIRECT)) {
            return;
        }
        int status = data.getStatus();
        // 检测 30x 状态码
        if (status < 300 || status >= 400) {
            return;
        }
        // 如果线程中断，不继续往下执行
        if (Thread.currentThread().isInterrupted()) {
            Logger.debug("handleFollowRedirect: thread pool is shutdown, intercept data id: %s", data.getId());
            return;
        }
        // 解析响应头的 Location 值
        IHttpRequestResponse reqResp = (IHttpRequestResponse) data.getReqResp();
        IResponseInfo respInfo = mHelpers.analyzeResponse(reqResp.getResponse());
        String location = getLocationByResponseInfo(respInfo);
        if (location == null) {
            return;
        }
        // 如果启用了 Cookie 跟随，获取响应头中的 Cookie 值
        List<String> cookies = null;
        if (Config.getBoolean(Config.KEY_REDIRECT_COOKIES_FOLLOW)) {
            cookies = getCookieByResponseInfo(respInfo);
        }
        String reqHost = data.getHost();
        String reqPath = data.getUrl();
        try {
            HttpReqRespAdapter httpReqResp;
            IRequestInfo reqInfo = mHelpers.analyzeRequest(reqResp);
            List<String> headers = reqInfo.getHeaders();
            // 兼容完整 Host 地址
            if (UrlUtils.isHTTP(reqPath)) {
                URL originUrl = UrlUtils.parseURL(reqPath);
                URL redirectUrl = UrlUtils.parseRedirectTargetURL(originUrl, location);
                IHttpService service = reqResp.getHttpService();
                httpReqResp = HttpReqRespAdapter.from(service, redirectUrl.toString(), headers, cookies);
            } else {
                URL originUrl = UrlUtils.parseURL(reqHost + reqPath);
                URL redirectUrl = UrlUtils.parseRedirectTargetURL(originUrl, location);
                IHttpService service = buildHttpServiceByURL(redirectUrl);
                httpReqResp = HttpReqRespAdapter.from(service, UrlUtils.toPQF(redirectUrl), headers, cookies);
            }
            doScan(httpReqResp, FROM_REDIRECT + "（" + data.getId() + "）");
        } catch (IllegalArgumentException e) {
            Logger.error("Follow redirect error: " + e.getMessage());
        }
    }

    /**
     * 从 IResponseInfo 实例获取响应头 Location 值
     *
     * @param info IResponseInfo 实例
     * @return 失败返回null
     */
    private String getLocationByResponseInfo(IResponseInfo info) {
        String headerPrefix = "location: ";
        List<String> headers = info.getHeaders();
        for (int i = 1; i < headers.size(); i++) {
            String header = headers.get(i);
            // 检测时忽略大小写
            if (header.toLowerCase().startsWith(headerPrefix)) {
                return header.substring(headerPrefix.length());
            }
        }
        return null;
    }

    /**
     * 从 IResponseInfo 实例获取响应头 Set-Cookie 值，并转换为请求头的 Cookie 值列表
     *
     * @param info IResponseInfo 实例
     * @return 失败返回空列表
     */
    private List<String> getCookieByResponseInfo(IResponseInfo info) {
        List<ICookie> respCookies = info.getCookies();
        List<String> cookies = new ArrayList<>();
        for (ICookie cookie : respCookies) {
            String name = cookie.getName();
            String value = cookie.getValue();
            // 拼接后，添加到列表
            cookies.add(String.format("%s=%s", name, value));
        }
        return cookies;
    }

    /**
     * 调用 BurpSuite 请求方式
     *
     * @param service     请求目标服务实例
     * @param reqRawBytes 请求数据包
     * @param retryCount  重试次数（为0表示不重试）
     * @return 请求响应数据
     */
    private IHttpRequestResponse doMakeHttpRequest(IHttpService service, byte[] reqRawBytes, int retryCount) {
        IHttpRequestResponse reqResp;
        String reqHost = getReqHostByHttpService(service);
        // 如果启用拦截超时主机，并检测到当前请求主机超时，直接拦截
        if (Config.getBoolean(Config.KEY_INTERCEPT_TIMEOUT_HOST) && checkTimeoutByReqHost(reqHost)) {
            return HttpReqRespAdapter.from(service, reqRawBytes);
        }
        try {
            reqResp = mCallbacks.makeHttpRequest(service, reqRawBytes);
            byte[] respRawBytes = reqResp.getResponse();
            if (respRawBytes != null && respRawBytes.length > 0) {
                return reqResp;
            }
        } catch (Exception e) {
            Logger.debug("Do Request error, request host: %s", reqHost);
            reqResp = HttpReqRespAdapter.from(service, reqRawBytes);
        }
        // 如果线程中断，不继续往下执行
        if (Thread.currentThread().isInterrupted()) {
            Logger.debug("doMakeHttpRequest: thread pool is shutdown, intercept task");
            return reqResp;
        }
        Logger.debug("Check retry request host: %s, count: %d", reqHost, retryCount);
        // 检测是否需要重试
        if (retryCount <= 0) {
            // 超时的请求，直接添加到集合中
            sTimeoutReqHost.add(reqHost);
            return reqResp;
        }
        // 获取配置的请求重试间隔时间
        int retryInterval = Config.getInt(Config.KEY_RETRY_INTERVAL);
        if (retryInterval > 0) {
            try {
                Thread.sleep(retryInterval);
            } catch (InterruptedException e) {
                // 如果线程中断，返回目前的响应结果
                return reqResp;
            }
        }
        // 请求重试
        return doMakeHttpRequest(service, reqRawBytes, retryCount - 1);
    }

    /**
     * 检测当前请求主机是否超时
     *
     * @param reqHost Host（格式：http://x.x.x.x、http://x.x.x.x:8080）
     * @return true=存在；false=不存在
     */
    private boolean checkTimeoutByReqHost(String reqHost) {
        if (sTimeoutReqHost.isEmpty()) {
            return false;
        }
        return sTimeoutReqHost.contains(reqHost);
    }

    /**
     * 处理请求头
     *
     * @param httpReqResp   Burp 的 HTTP 请求响应接口
     * @param pathWithQuery 请求路径，或者请求路径+Query（示例：/xxx、/xxx/index?a=xxx&b=xxx）
     * @param from          数据来源
     * @return 处理完成的数据包，失败时返回null
     */
    private byte[] handleHeader(IHttpRequestResponse httpReqResp, IRequestInfo info, String pathWithQuery, String from) {
        // 配置的请求头
        List<String> configHeader = getHeader();
        // 要移除的请求头KEY列表
        List<String> removeHeaders = getRemoveHeaders();
        // 数据包自带的请求头
        List<String> headers = info.getHeaders();
        // 构建请求头
        StringBuilder requestRaw = new StringBuilder();
        // 根据数据来源区分两种请求头
        if (from.equals(FROM_SCAN)) {
            requestRaw.append("GET ").append(pathWithQuery).append(" HTTP/1.1").append("\r\n");
        } else {
            String reqLine = headers.get(0);
            // 先检测一下是否包含 ' HTTP/' 字符串，再继续处理（可能有些畸形数据包不存在该内容）
            if (reqLine.contains(" HTTP/")) {
                int start = reqLine.lastIndexOf(" HTTP/");
                reqLine = reqLine.substring(0, start) + " HTTP/1.1";
            }
            requestRaw.append(reqLine).append("\r\n");
        }
        // 请求头的参数处理（顺带处理移除的请求头），从 1 开始表示跳过首行（请求行）
        for (int i = 1; i < headers.size(); i++) {
            String item = headers.get(i);
            String key = item.split(": ")[0];
            // 是否需要移除当前请求头字段（优先级最高）
            if (removeHeaders.contains(key)) {
                continue;
            }
            // 如果是扫描的请求（只有 GET 请求），将 Content-Length 移除
            if (from.equals(FROM_SCAN) && "Content-Length".equalsIgnoreCase(key)) {
                continue;
            }
            // 检测配置中是否存在当前请求头字段
            String matchItem = configHeader.stream().filter(configHeaderItem -> {
                if (StringUtils.isNotEmpty(configHeaderItem) && configHeaderItem.contains(": ")) {
                    String configHeaderKey = configHeaderItem.split(": ")[0];
                    // 检测是否需要移除当前请求头字段
                    if (removeHeaders.contains(key)) {
                        return false;
                    }
                    return configHeaderKey.equals(key);
                }
                return false;
            }).findFirst().orElse(null);
            // 配置中存在匹配项，替换为配置中的数据
            if (matchItem != null) {
                requestRaw.append(matchItem).append("\r\n");
                // 将已经添加的数据从列表中移除
                configHeader.remove(matchItem);
            } else {
                // 不存在匹配项，填充原数据
                requestRaw.append(item).append("\r\n");
            }
        }
        // 将配置里剩下的值全部填充到请求头中
        for (String item : configHeader) {
            String key = item.split(": ")[0];
            // 检测是否需要移除当前KEY
            if (!removeHeaders.contains(key)) {
                requestRaw.append(item).append("\r\n");
            }
        }
        requestRaw.append("\r\n");
        // 如果当前数据来源不是 Scan，可能会包含 POST 请求，判断是否存在 body 数据
        if (!from.equals(FROM_SCAN)) {
            byte[] httpRequest = httpReqResp.getRequest();
            int bodyOffset = info.getBodyOffset();
            int bodySize = httpRequest.length - bodyOffset;
            if (bodySize > 0) {
                requestRaw.append(new String(httpRequest, bodyOffset, bodySize));
            }
        }
        // 请求头构建完成后，对里面包含的动态变量进行赋值
        IHttpService service = httpReqResp.getHttpService();
        URL url = getUrlByRequestInfo(info);
        String newRequestRaw = setupVariable(service, url, requestRaw.toString());
        if (newRequestRaw == null) {
            return null;
        }
        // 更新 Content-Length
        return updateContentLength(mHelpers.stringToBytes(newRequestRaw));
    }

    /**
     * 获取请求头配置
     */
    private List<String> getHeader() {
        if (!mDataBoardTab.hasReplaceHeader()) {
            return new ArrayList<>();
        }
        return WordlistManager.getHeader();
    }

    /**
     * 获取移除请求头列表配置
     */
    private List<String> getRemoveHeaders() {
        if (!mDataBoardTab.hasRemoveHeader()) {
            return new ArrayList<>();
        }
        return WordlistManager.getRemoveHeaders();
    }

    /**
     * 获取配置的 Payload Processing 规则
     */
    private List<ProcessingItem> getPayloadProcess() {
        ArrayList<ProcessingItem> list = Config.getPayloadProcessList();
        if (list == null) {
            return new ArrayList<>();
        }
        return list.stream().filter(ProcessingItem::isEnabled).collect(Collectors.toList());
    }

    /**
     * 检测 QPS 限制
     *
     * @return true=拦截；false=不拦截
     */
    private boolean checkQPSLimit() {
        if (mQpsLimit != null) {
            try {
                mQpsLimit.limit();
            } catch (InterruptedException e) {
                // 线程强制停止时，拦截请求
                return true;
            }
        }
        return false;
    }

    /**
     * 给数据包填充动态变量
     *
     * @param service    请求目标实例
     * @param url        请求 URL 实例
     * @param requestRaw 请求数据包字符串
     * @return 处理失败返回null
     */
    private String setupVariable(IHttpService service, URL url, String requestRaw) {
        String protocol = service.getProtocol();
        String host = service.getHost() + ":" + service.getPort();
        if (service.getPort() == 80 || service.getPort() == 443) {
            host = service.getHost();
        }
        String domain = service.getHost();
        String timestamp = String.valueOf(DateUtils.getTimestamp());
        String randomIP = IPUtils.randomIPv4();
        String randomLocalIP = IPUtils.randomIPv4ForLocal();
        String randomUA = Utils.getRandomItem(WordlistManager.getUserAgent());
        String domainMain = DomainHelper.getDomain(domain, null);
        String domainName = DomainHelper.getDomainName(domain, null);
        String subdomain = getSubdomain(domain);
        String subdomains = getSubdomains(domain);
        String webroot = getWebrootByURL(url);
        // 替换变量
        try {
            requestRaw = fillVariable(requestRaw, "protocol", protocol);
            requestRaw = fillVariable(requestRaw, "host", host);
            requestRaw = fillVariable(requestRaw, "webroot", webroot);
            // 需要填充再取值
            if (requestRaw.contains("{{ip}}")) {
                String ip = findIpByHost(domain);
                requestRaw = fillVariable(requestRaw, "ip", ip);
            }
            // 填充域名相关动态变量
            requestRaw = fillVariable(requestRaw, "domain", domain);
            requestRaw = fillVariable(requestRaw, "domain.main", domainMain);
            requestRaw = fillVariable(requestRaw, "domain.name", domainName);
            // 填充子域名相关动态变量
            requestRaw = fillVariable(requestRaw, "subdomain", subdomain);
            requestRaw = fillVariable(requestRaw, "subdomains", subdomains);
            if (requestRaw.contains("{{subdomains.")) {
                if (StringUtils.isEmpty(subdomains)) {
                    return null;
                }
                String[] subdomainsSplit = subdomains.split("\\.");
                // 遍历填充 {{subdomains.%d}} 动态变量
                for (int i = 0; i < subdomainsSplit.length; i++) {
                    requestRaw = fillVariable(requestRaw, "subdomains." + i, subdomainsSplit[i]);
                }
                // 检测是否存在未填充的 {{subdomains.%d}} 动态变量，如果存在，忽略当前 Payload
                if (requestRaw.contains("{{subdomains.")) {
                    return null;
                }
            }
            // 填充随机值相关动态变量
            requestRaw = fillVariable(requestRaw, "random.ip", randomIP);
            requestRaw = fillVariable(requestRaw, "random.local-ip", randomLocalIP);
            requestRaw = fillVariable(requestRaw, "random.ua", randomUA);
            // 填充日期、时间相关的动态变量
            requestRaw = fillVariable(requestRaw, "timestamp", timestamp);
            if (requestRaw.contains("{{date.") || requestRaw.contains("{{time.")) {
                String currentDate = DateUtils.getCurrentDate("yyyy-MM-dd HH:mm:ss;yy-M-d H:m:s");
                String[] split = currentDate.split(";");
                String[] leftDateTime = parseDateTime(split[0]);
                requestRaw = fillVariable(requestRaw, "date.yyyy", leftDateTime[0]);
                requestRaw = fillVariable(requestRaw, "date.MM", leftDateTime[1]);
                requestRaw = fillVariable(requestRaw, "date.dd", leftDateTime[2]);
                requestRaw = fillVariable(requestRaw, "time.HH", leftDateTime[3]);
                requestRaw = fillVariable(requestRaw, "time.mm", leftDateTime[4]);
                requestRaw = fillVariable(requestRaw, "time.ss", leftDateTime[5]);
                String[] rightDateTime = parseDateTime(split[1]);
                requestRaw = fillVariable(requestRaw, "date.yy", rightDateTime[0]);
                requestRaw = fillVariable(requestRaw, "date.M", rightDateTime[1]);
                requestRaw = fillVariable(requestRaw, "date.d", rightDateTime[2]);
                requestRaw = fillVariable(requestRaw, "time.H", rightDateTime[3]);
                requestRaw = fillVariable(requestRaw, "time.m", rightDateTime[4]);
                requestRaw = fillVariable(requestRaw, "time.s", rightDateTime[5]);
            }
            return requestRaw;
        } catch (IllegalArgumentException e) {
            Logger.debug(e.getMessage());
            return null;
        }
    }

    /**
     * 填充动态变量
     *
     * @param src   数据源
     * @param name  变量名
     * @param value 需要填充的变量值
     * @throws IllegalArgumentException 当填充的变量值为空时，抛出该异常
     */
    private String fillVariable(String src, String name, String value) throws IllegalArgumentException {
        if (StringUtils.isEmpty(src)) {
            return src;
        }
        String key = String.format("{{%s}}", name);
        if (!src.contains(key)) {
            return src;
        }
        // 值为空时，返回null值丢弃当前请求
        if (StringUtils.isEmpty(value)) {
            throw new IllegalArgumentException(key + " fill failed, value is empty.");
        }
        return src.replace(key, value);
    }

    /**
     * 解析日期时间，将每个字段的数据存入数组
     *
     * @param dateTime 日期时间字符串（格式：yyyy-MM-dd HH:mm:ss 或者 yy-M-d H:m:s）
     * @return [0]=年；[1]=月；[2]=日；[3]=时；[4]=分；[5]=秒
     */
    private String[] parseDateTime(String dateTime) {
        String[] result = new String[6];
        String[] split = dateTime.split(" ");
        // 日期
        String date = split[0];
        String[] dateSplit = date.split("-");
        result[0] = dateSplit[0];
        result[1] = dateSplit[1];
        result[2] = dateSplit[2];
        // 时间
        String time = split[1];
        String[] timeSplit = time.split(":");
        result[3] = timeSplit[0];
        result[4] = timeSplit[1];
        result[5] = timeSplit[2];
        return result;
    }

    /**
     * 获取子域名
     *
     * @param domain 域名（格式示例：www.xxx.com）
     * @return 格式：www；如果没有子域名，或者获取失败，返回null
     */
    private String getSubdomain(String domain) {
        String subdomains = getSubdomains(domain);
        if (StringUtils.isEmpty(subdomains)) {
            return null;
        }
        if (subdomains.contains(".")) {
            return subdomains.substring(0, subdomains.indexOf("."));
        }
        return subdomains;
    }

    /**
     * 获取完整子域名
     *
     * @param domain 域名（格式示例：api.xxx.com、api.admin.xxx.com）
     * @return 格式：api、api.admin；如果没有子域名，或者获取失败，返回null
     */
    private String getSubdomains(String domain) {
        if (IPUtils.hasIPv4(domain)) {
            return null;
        }
        if (!domain.contains(".")) {
            return null;
        }
        String parseDomain = DomainHelper.getDomain(domain, null);
        if (StringUtils.isEmpty(parseDomain)) {
            return null;
        }
        int endIndex = domain.lastIndexOf(parseDomain) - 1;
        if (endIndex < 0) {
            return null;
        }
        return domain.substring(0, endIndex);
    }

    /**
     * 从URL实例中获取Web根目录名（例如："http://xxx.com/abc/a.php" => "abc"）
     *
     * @param url URL实例
     * @return 失败返回null
     */
    private String getWebrootByURL(URL url) {
        if (url == null) {
            return null;
        }
        String path = url.getPath();
        // 没有根目录名，直接返回null
        if (StringUtils.isEmpty(path) || "/".equals(path)) {
            return null;
        }
        // 找第二个'/'斜杠
        int end = path.indexOf("/", 1);
        if (end < 0) {
            return null;
        }
        // 找到之后，取中间的值
        return path.substring(1, end);
    }

    /**
     * 根据 Payload Process 规则，处理数据包
     *
     * @param service      请求目标服务
     * @param requestBytes 请求数据包
     * @return 处理后的数据包
     */
    private byte[] handlePayloadProcess(IHttpService service, byte[] requestBytes, List<PayloadItem> list) {
        if (requestBytes == null || requestBytes.length == 0 || list == null || list.isEmpty()) {
            return null;
        }
        IRequestInfo info = mHelpers.analyzeRequest(service, requestBytes);
        int bodyOffset = info.getBodyOffset();
        int bodySize = requestBytes.length - bodyOffset;
        String url = getReqPathByRequestInfo(info);
        String header = new String(requestBytes, 0, bodyOffset - 4);
        String body = bodySize <= 0 ? "" : new String(requestBytes, bodyOffset, bodySize);
        String request = mHelpers.bytesToString(requestBytes);
        for (PayloadItem item : list) {
            // 只调用启用的规则
            PayloadRule rule = item.getRule();
            try {
                switch (item.getScope()) {
                    case PayloadRule.SCOPE_URL:
                        String newUrl = rule.handleProcess(url);
                        // 截取请求头第一行，用于定位要处理的位置
                        String reqLine = header.substring(0, header.indexOf("\r\n"));
                        Matcher matcher = Constants.REGEX_REQ_LINE_URL.matcher(reqLine);
                        if (matcher.find()) {
                            int start = matcher.start(1);
                            int end = matcher.end(1);
                            // 分隔要插入数据的位置
                            String left = header.substring(0, start);
                            String right = header.substring(end);
                            // 拼接处理好的数据
                            header = left + newUrl + right;
                            request = header + "\r\n\r\n" + body;
                        }
                        url = newUrl;
                        break;
                    case PayloadRule.SCOPE_HEADER:
                        String newHeader = rule.handleProcess(header);
                        header = newHeader;
                        request = newHeader + "\r\n\r\n" + body;
                        break;
                    case PayloadRule.SCOPE_BODY:
                        String newBody = rule.handleProcess(body);
                        request = header + "\r\n\r\n" + newBody;
                        body = newBody;
                        break;
                    case PayloadRule.SCOPE_REQUEST:
                        request = rule.handleProcess(request);
                        break;
                }
            } catch (Exception e) {
                Logger.debug("handlePayloadProcess exception: " + e.getMessage());
                return null;
            }
        }
        // 动态变量赋值
        URL u = getUrlByRequestInfo(info);
        String newRequest = setupVariable(service, u, request);
        if (newRequest == null) {
            return null;
        }
        // 更新 Content-Length
        return updateContentLength(mHelpers.stringToBytes(newRequest));
    }

    /**
     * 更新 Content-Length 参数值
     *
     * @param rawBytes 请求数据包
     * @return 更新后的数据包
     */
    private byte[] updateContentLength(byte[] rawBytes) {
        String temp = new String(rawBytes, StandardCharsets.US_ASCII);
        int bodyOffset = temp.indexOf("\r\n\r\n");
        if (bodyOffset == -1) {
            Logger.error("Handle payload process error: bodyOffset is -1");
            return null;
        }
        bodyOffset += 4;
        int bodySize = rawBytes.length - bodyOffset;
        if (bodySize < 0) {
            Logger.error("Handle payload process error: bodySize < 0");
            return null;
        } else if (bodySize == 0) {
            return rawBytes;
        }
        String header = new String(rawBytes, 0, bodyOffset - 4);
        if (!header.contains("Content-Length")) {
            header += "\r\nContent-Length: " + bodySize;
        } else {
            header = header.replaceAll("Content-Length:.*", "Content-Length: " + bodySize);
        }
        String body = new String(rawBytes, bodyOffset, bodySize);
        String result = header + "\r\n\r\n" + body;
        return result.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * 构建Item数据
     *
     * @param httpReqResp Burp的请求响应对象
     * @return 列表Item数据
     */
    private TaskData buildTaskData(IHttpRequestResponse httpReqResp, String from) {
        IRequestInfo info = mHelpers.analyzeRequest(httpReqResp);
        byte[] respBytes = httpReqResp.getResponse();
        // 获取所需要的参数
        String method = info.getMethod();
        IHttpService service = httpReqResp.getHttpService();
        String reqHost = getReqHostByHttpService(service);
        String reqUrl = getReqPathByRequestInfo(info);
        String title = HtmlUtils.findTitleByHtmlBody(respBytes);
        String ip = findIpByHost(service.getHost());
        int status = -1;
        int length = -1;
        // 存在响应对象，获取状态和响应包大小
        if (respBytes != null && respBytes.length > 0) {
            IResponseInfo response = mHelpers.analyzeResponse(respBytes);
            status = response.getStatusCode();
            // 处理响应 body 的长度
            length = respBytes.length - response.getBodyOffset();
            if (length < 0) {
                length = 0;
            }
        }
        // 检测指纹数据
        List<FpData> checkResult = FpManager.check(httpReqResp.getRequest(), httpReqResp.getResponse());
        // 构建表格对象
        TaskData data = new TaskData();
        data.setFrom(from);
        data.setMethod(method);
        data.setHost(reqHost);
        data.setUrl(reqUrl);
        data.setTitle(title);
        data.setIp(ip);
        data.setStatus(status);
        data.setLength(length);
        data.setFingerprint(checkResult);
        data.setReqResp(httpReqResp);
        return data;
    }

    /**
     * 通过 IHttpService 实例，获取请求的 Host 地址（http://x.x.x.x、http://x.x.x.x:8080）
     *
     * @param service IHttpService 实例
     * @return 返回请求的 Host 地址
     */
    private String getReqHostByHttpService(IHttpService service) {
        String protocol = service.getProtocol();
        String host = service.getHost();
        int port = service.getPort();
        if (Utils.isIgnorePort(port)) {
            return protocol + "://" + host;
        }
        return protocol + "://" + host + ":" + port;
    }

    /**
     * 通过 IHttpService 实例，获取请求的 Host 值（示例格式：x.x.x.x、x.x.x.x:8080）
     *
     * @return 失败返回null
     */
    public static String getHostByHttpService(IHttpService service) {
        if (service == null) {
            return null;
        }
        String host = service.getHost();
        int port = service.getPort();
        if (Utils.isIgnorePort(port)) {
            return host;
        }
        return host + ":" + port;
    }

    /**
     * 通过 URL 实例，构建 IHttpService 实例
     *
     * @return 失败返回null
     */
    public static IHttpService buildHttpServiceByURL(URL url) {
        if (url == null) {
            return null;
        }
        return new IHttpService() {
            @Override
            public String getHost() {
                return url.getHost();
            }

            @Override
            public int getPort() {
                String protocol = getProtocol();
                int port = url.getPort();
                if (port == -1) {
                    port = protocol.equals("https") ? 443 : 80;
                }
                return port;
            }

            @Override
            public String getProtocol() {
                return url.getProtocol();
            }
        };
    }

    /**
     * 根据 Host 查询 IP 地址
     *
     * @param host Host 值
     * @return 失败返回空字符串
     */
    private String findIpByHost(String host) {
        if (IPUtils.hasIPv4(host)) {
            return host;
        }
        try {
            InetAddress ip = InetAddress.getByName(host);
            return ip.getHostAddress();
        } catch (UnknownHostException e) {
            return "";
        }
    }

    /**
     * 获取 IRequestInfo 实例的请求 URL 实例
     *
     * @param info IRequestInfo 实例
     * @return 返回请求的 URL 实例
     */
    private URL getUrlByRequestInfo(IRequestInfo info) {
        URL url = info.getUrl();
        try {
            // 分两种情况，一种是完整 Host 地址，还有一种是普通请求路径
            String reqPath = getReqPathByRequestInfo(info);
            if (UrlUtils.isHTTP(reqPath)) {
                return new URL(reqPath);
            }
            // 普通请求路径因为 IRequestInfo.getUrl 方法有时候获取的值不准确，重新解析一下
            String reqHost = UrlUtils.getReqHostByURL(url);
            return new URL(reqHost + reqPath);
        } catch (Exception e) {
            Logger.error("getUrlByRequestInfo: convert url error: %s", e.getMessage());
            return url;
        }
    }

    @Override
    public IHttpService getHttpService() {
        if (mCurrentReqResp != null) {
            return mCurrentReqResp.getHttpService();
        }
        return null;
    }

    @Override
    public byte[] getRequest() {
        if (mCurrentReqResp != null) {
            return mCurrentReqResp.getRequest();
        }
        return new byte[0];
    }

    @Override
    public byte[] getResponse() {
        if (mCurrentReqResp != null) {
            return mCurrentReqResp.getResponse();
        }
        return new byte[0];
    }

    @Override
    public void onChangeSelection(TaskData data) {
        // 如果 data 为空，表示执行了清空历史记录操作
        if (data == null) {
            onClearHistory();
            return;
        }
        mCurrentReqResp = (IHttpRequestResponse) data.getReqResp();
        // 加载请求、响应数据包
        byte[] hintBytes = mHelpers.stringToBytes(L.get("message_editor_loading"));
        mRequestTextEditor.setMessage(hintBytes, true);
        mResponseTextEditor.setMessage(hintBytes, false);
        mRefreshMsgTask.execute(this::refreshReqRespMessage);
    }

    /**
     * 清空历史记录
     */
    private void onClearHistory() {
        mCurrentReqResp = null;
        // 清空去重过滤集合
        sRepeatFilter.clear();
        // 清空超时的请求主机集合
        sTimeoutReqHost.clear();
        // 清空显示的请求、响应数据包
        mRequestTextEditor.setMessage(EMPTY_BYTES, true);
        mResponseTextEditor.setMessage(EMPTY_BYTES, false);
        // 清除指纹识别历史记录
        FpManager.clearHistory();
    }

    /**
     * 刷新请求响应信息
     */
    private void refreshReqRespMessage() {
        byte[] request = getRequest();
        byte[] response = getResponse();
        if (request == null || request.length == 0) {
            request = EMPTY_BYTES;
        }
        if (response == null || response.length == 0) {
            response = EMPTY_BYTES;
        }
        // 检测是否超过配置的显示长度限制
        int maxLength = Config.getInt(Config.KEY_MAX_DISPLAY_LENGTH);
        if (maxLength >= 100000 && request.length >= maxLength) {
            String hint = L.get("message_editor_request_length_limit_hint");
            request = mHelpers.stringToBytes(hint);
        }
        if (maxLength >= 100000 && response.length >= maxLength) {
            String hint = L.get("message_editor_response_length_limit_hint");
            response = mHelpers.stringToBytes(hint);
        }
        mRequestTextEditor.setMessage(request, true);
        mResponseTextEditor.setMessage(response, false);
    }

    @Override
    public void onSendToRepeater(ArrayList<TaskData> list) {
        if (list == null || list.isEmpty()) {
            return;
        }
        for (TaskData data : list) {
            if (data.getReqResp() == null) {
                continue;
            }
            byte[] reqBytes = ((IHttpRequestResponse) data.getReqResp()).getRequest();
            String url = data.getHost() + data.getUrl();
            try {
                URL u = new URL(url);
                int port = u.getPort();
                boolean useHttps = "https".equalsIgnoreCase(u.getProtocol());
                if (port == -1) {
                    port = useHttps ? 443 : 80;
                }
                mCallbacks.sendToRepeater(u.getHost(), port, useHttps, reqBytes, null);
            } catch (Exception e) {
                Logger.debug(e.getMessage());
            }
        }
    }

    @Override
    public byte[] getBodyByTaskData(TaskData data) {
        if (data == null || data.getReqResp() == null) {
            return new byte[]{};
        }
        mCurrentReqResp = (IHttpRequestResponse) data.getReqResp();
        byte[] respBytes = mCurrentReqResp.getResponse();
        if (respBytes == null || respBytes.length == 0) {
            return new byte[]{};
        }
        IResponseInfo info = mCallbacks.getHelpers().analyzeResponse(respBytes);
        int offset = info.getBodyOffset();
        return Arrays.copyOfRange(respBytes, offset, respBytes.length);
    }

    @Override
    public void addHostToBlocklist(ArrayList<String> hosts) {
        if (hosts == null || hosts.isEmpty()) {
            return;
        }
        List<String> list = WordlistManager.getList(WordlistManager.KEY_HOST_BLOCKLIST);
        for (String host : hosts) {
            if (!list.contains(host)) {
                list.add(host);
            }
        }
        WordlistManager.putList(WordlistManager.KEY_HOST_BLOCKLIST, list);
        mOneScan.getConfigPanel().refreshHostTab();
    }

    @Override
    public void onTabEventMethod(String action, Object... params) {
        switch (action) {
            case RequestTab.EVENT_QPS_LIMIT:
                changeQpsLimit(String.valueOf(params[0]));
                break;
            case RequestTab.EVENT_REQUEST_DELAY:
                changeRequestDelay(String.valueOf(params[0]));
                break;
            case OtherTab.EVENT_UNLOAD_PLUGIN:
                mCallbacks.unloadExtension();
                break;
            case DataBoardTab.EVENT_IMPORT_URL:
                importUrl((List<?>) params[0]);
                break;
            case DataBoardTab.EVENT_STOP_TASK:
                stopAllTask();
                break;
        }
    }

    /**
     * 修改 QPS 限制
     *
     * @param limit QPS 限制值（数字）
     */
    private void changeQpsLimit(String limit) {
        initQpsLimiter();
        Logger.debug("Event: change qps limit: %s", limit);
    }

    /**
     * 修改请求延迟
     *
     * @param delay 延迟的值（数字）
     */
    private void changeRequestDelay(String delay) {
        initQpsLimiter();
        Logger.debug("Event: change request delay: %s", delay);
    }

    /**
     * 导入 URL
     *
     * @param list URL 列表
     */
    private void importUrl(List<?> list) {
        if (list == null || list.isEmpty()) {
            return;
        }
        // 处理导入的 URL 数据
        new Thread(() -> {
            for (Object item : list) {
                try {
                    String url = String.valueOf(item);
                    IHttpRequestResponse httpReqResp = HttpReqRespAdapter.from(url);
                    doScan(httpReqResp, FROM_IMPORT);
                } catch (IllegalArgumentException e) {
                    Logger.error("Import error: " + e.getMessage());
                }
                // 线程池关闭后，停止导入 Url 数据
                if (isTaskThreadPoolShutdown()) {
                    Logger.debug("importUrl: thread pool is shutdown, stop import url");
                    return;
                }
            }
        }).start();
    }

    /**
     * 停止扫描中的所有任务
     */
    private void stopAllTask() {
        // 关闭线程池，处理未执行的任务
        List<Runnable> taskList = mTaskThreadPool.shutdownNow();
        List<Runnable> lfTaskList = mLFTaskThreadPool.shutdownNow();
        handleStopTasks(taskList);
        handleStopTasks(lfTaskList);
        // 提示信息
        UIHelper.showTipsDialog(L.get("stop_task_tips"));
        // 停止后，重新初始化任务线程池
        mTaskThreadPool = Executors.newFixedThreadPool(TASK_THREAD_COUNT);
        // 停止后，重新初始化低频任务线程池
        mLFTaskThreadPool = Executors.newFixedThreadPool(LF_TASK_THREAD_COUNT);
        // 重新初始化 QPS 限制器
        initQpsLimiter();
    }

    /**
     * 处理停止的任务列表
     *
     * @param list 任务列表
     */
    private void handleStopTasks(List<Runnable> list) {
        if (list == null || list.isEmpty()) {
            return;
        }
        for (Runnable run : list) {
            if (run instanceof TaskRunnable) {
                TaskRunnable task = (TaskRunnable) run;
                String reqId = task.getReqId();
                String from = task.getFrom();
                // 将未执行的任务从去重过滤集合中移除
                sRepeatFilter.remove(reqId);
                // 将未执行的任务计数
                if (isLowFrequencyTask(from)) {
                    mLFTaskOverCounter.incrementAndGet();
                } else {
                    mTaskOverCounter.incrementAndGet();
                }
            }
        }
    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController iMessageEditorController, boolean editable) {
        return new OneScanInfoTab(mCallbacks, iMessageEditorController);
    }

    @Override
    public void extensionUnloaded() {
        // 移除代理监听器
        mCallbacks.removeProxyListener(this);
        // 移除插件卸载监听器
        mCallbacks.removeExtensionStateListener(this);
        // 移除信息辅助面板
        mCallbacks.removeMessageEditorTabFactory(this);
        // 移除注册的菜单
        mCallbacks.removeContextMenuFactory(this);
        // 停止状态栏刷新定时器
        mStatusRefresh.stop();
        // 关闭任务线程池
        int count = mTaskThreadPool.shutdownNow().size();
        Logger.info("Close: task thread pool completed. Task %d records.", count);
        // 关闭低频任务线程池
        count = mLFTaskThreadPool.shutdownNow().size();
        Logger.info("Close: low frequency task thread pool completed. Task %d records.", count);
        // 关闭指纹识别线程池
        count = mFpThreadPool.shutdownNow().size();
        Logger.info("Close: fingerprint recognition thread pool completed. Task %d records.", count);
        // 关闭数据收集线程池
        count = CollectManager.closeThreadPool();
        Logger.info("Close: data collection thread pool completed. Task %d records.", count);
        // 清除数据收集的去重过滤集合
        count = CollectManager.getRepeatFilterCount();
        CollectManager.clearRepeatFilter();
        Logger.info("Clear: data collection repeat filter list completed. Total %d records.", count);
        // 清除指纹识别缓存
        count = FpManager.getCacheCount();
        FpManager.clearCache();
        Logger.info("Clear: fingerprint recognition cache completed. Total %d records.", count);
        // 清除指纹识别历史记录
        count = FpManager.getHistoryCount();
        FpManager.clearHistory();
        Logger.info("Clear: fingerprint recognition history completed. Total %d records.", count);
        // 清除指纹字段修改监听器
        FpManager.clearsFpColumnModifyListeners();
        // 清除去重过滤集合
        count = sRepeatFilter.size();
        sRepeatFilter.clear();
        Logger.info("Clear: repeat filter list completed. Total %d records.", count);
        // 清除超时的请求主机集合
        count = sTimeoutReqHost.size();
        sTimeoutReqHost.clear();
        Logger.info("Clear: timeout request host list completed. Total %d records.", count);
        // 清除任务列表
        count = 0;
        if (mDataBoardTab != null) {
            TaskTable taskTable = mDataBoardTab.getTaskTable();
            if (taskTable != null) {
                count = taskTable.getTaskCount();
                taskTable.clearAll();
            }
            // 关闭导入 URL 窗口
            mDataBoardTab.closeImportUrlWindow();
        }
        Logger.info("Clear: task list completed. Total %d records.", count);
        // 关闭指纹相关窗口
        if (mOneScan != null && mOneScan.getFingerprintTab() != null) {
            FingerprintTab tab = mOneScan.getFingerprintTab();
            // 指纹测试窗口
            tab.closeFpTestWindow();
            // 指纹字段管理窗口
            tab.closeFpColumnManagerWindow();
        }
        // 卸载完成
        Logger.info(Constants.UNLOAD_BANNER);
    }


}