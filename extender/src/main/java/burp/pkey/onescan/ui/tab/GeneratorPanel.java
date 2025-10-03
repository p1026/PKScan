package burp.pkey.onescan.ui.tab;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IMessageEditor;
import burp.IMessageEditorController;
import burp.IRequestInfo;
import burp.ITab;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IIntruderPayloadGenerator;
import burp.IIntruderPayloadGeneratorFactory;
import burp.IIntruderAttack;
import java.awt.*;
import java.awt.datatransfer.*;
import java.awt.event.*;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;
import java.util.List;
import java.util.AbstractMap.SimpleEntry;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.*;
import javax.swing.Timer;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;

public class GeneratorPanel implements ITab {
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final JPanel mainPanel;
    private final JTabbedPane generatorTabs;
    private int newTabIndex = 0;
    private static final List<String> GLOBAL_PAYLOADS = new ArrayList<>();

    // 五种请求类型常量
    private static final int REQUEST_TYPE_GET = 0;
    private static final int REQUEST_TYPE_FORM = 1;
    private static final int REQUEST_TYPE_JSON = 2;
    private static final int REQUEST_TYPE_MULTIPART = 3;
    private static final int REQUEST_TYPE_XML = 4;
    private static final int TOTAL_REQUEST_TYPES = 5;

    // 保留File和Path类型
    public static final String[] PAYLOAD_TYPES = {"Param", "File", "Path", "FullPath", "Value"};
    public static final String[] VALUE_TYPES = {"random", "custom"};
    // 统一按钮尺寸常量
    private static final Dimension UNIFORM_BUTTON_SIZE = new Dimension(90, 25);

    public GeneratorPanel(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.mainPanel = new JPanel(new BorderLayout());
        this.generatorTabs = new JTabbedPane();

        callbacks.registerIntruderPayloadGeneratorFactory(new CustomPayloadGeneratorFactory());

        initGeneratorTabs();
        mainPanel.add(generatorTabs, BorderLayout.CENTER);
        callbacks.customizeUiComponent(mainPanel);
    }

    private void initGeneratorTabs() {
        generatorTabs.addTab("+", null);
        addNewGeneratorTab(null, "Param", "id");

        generatorTabs.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                int index = generatorTabs.indexAtLocation(e.getX(), e.getY());
                if (index == generatorTabs.getTabCount() - 1) {
                    addNewGeneratorTab(null, "Param", "id");
                }
            }
        });

        generatorTabs.setComponentPopupMenu(createTabPopupMenu());
    }

    private JPopupMenu createTabPopupMenu() {
        JPopupMenu popup = new JPopupMenu();

        JMenuItem renameItem = new JMenuItem("Rename");
        renameItem.addActionListener(e -> {
            int selected = generatorTabs.getSelectedIndex();
            if (selected != generatorTabs.getTabCount() - 1) {
                String newName = JOptionPane.showInputDialog("Enter new tab name:");
                if (newName != null && !newName.isEmpty()) {
                    generatorTabs.setTitleAt(selected, newName);
                }
            }
        });

        JMenuItem deleteItem = new JMenuItem("Delete");
        deleteItem.addActionListener(e -> {
            int selected = generatorTabs.getSelectedIndex();
            if (selected != generatorTabs.getTabCount() - 1 && generatorTabs.getTabCount() > 2) {
                generatorTabs.remove(selected);
            }
        });

        popup.add(renameItem);
        popup.add(deleteItem);
        return popup;
    }

    public void addNewGeneratorTab(IHttpRequestResponse request, String payloadType, String payloads) {
        String tabTitle = ""+newTabIndex++;
        GeneratorTabContent tabContent = new GeneratorTabContent(request, payloadType, payloads);
        generatorTabs.insertTab(tabTitle, null, tabContent, null, generatorTabs.getTabCount() - 1);
        generatorTabs.setSelectedIndex(generatorTabs.getTabCount() - 2);
    }

    @Override
    public String getTabCaption() {
        return "数据生成";
    }

    @Override
    public Component getUiComponent() {
        return mainPanel;
    }

    private class CustomPayloadGeneratorFactory implements IIntruderPayloadGeneratorFactory {
        @Override
        public String getGeneratorName() {
            return "PKScan Data Generator";
        }

        @Override
        public IIntruderPayloadGenerator createNewInstance(IIntruderAttack attack) {
            return new CustomPayloadGenerator();
        }
    }

    private static class CustomPayloadGenerator implements IIntruderPayloadGenerator {
        private int payloadIndex = 0;

        @Override
        public boolean hasMorePayloads() {
            return payloadIndex < GLOBAL_PAYLOADS.size();
        }

        @Override
        public byte[] getNextPayload(byte[] baseValue) {
            if (payloadIndex < GLOBAL_PAYLOADS.size()) {
                return GLOBAL_PAYLOADS.get(payloadIndex++).getBytes();
            }
            return new byte[0];
        }

        @Override
        public void reset() {
            payloadIndex = 0;
        }
    }

    private String generateRandomString(String charset, int length) {
        if (charset.isEmpty() || length <= 0) {
            return "";
        }

        StringBuilder sb = new StringBuilder();
        Random random = new Random();
        for (int i = 0; i < length; i++) {
            int index = random.nextInt(charset.length());
            sb.append(charset.charAt(index));
        }
        return sb.toString();
    }

    // 生成累积式参数的Payload (Param类型使用)
    private List<String> generateCumulativePayloads(List<Map.Entry<String, String>> allParams,
                                                    String requestTemplate, String path, String host) {
        List<String> allPayloads = new ArrayList<>();

        // 逐步添加参数，每次添加一个新参数并生成五种请求类型
        List<Map.Entry<String, String>> currentParams = new ArrayList<>();

        for (Map.Entry<String, String> param : allParams) {
            // 添加当前参数到参数列表
            currentParams.add(param);

            // 为当前参数集合生成五种请求类型
            List<String> currentPayloads = generateRequestTypesForParams(currentParams, requestTemplate, path, host);
            allPayloads.addAll(currentPayloads);
        }

        return allPayloads;
    }

    // 通用路径处理方法，供File和Path类型共用
    private List<String> generatePathBasedPayloads(List<String> pathEntries,
                                                   String requestTemplate, String basePath, String host,
                                                   boolean isFilePath) {
        List<String> allPayloads = new ArrayList<>();

        // 为每个路径项单独生成五种请求类型，不累积
        for (String pathEntry : pathEntries) {
            // 清理路径项，确保路径格式正确
            String cleanPathEntry = pathEntry.trim();
            if (cleanPathEntry.isEmpty()) continue;

            // 使用新的路径拼接方法
            String newPath = cleanAndJoinPath(basePath, cleanPathEntry);

            // 为当前路径生成五种请求类型，不带参数
            List<String> currentPayloads = generateRequestTypesForPath(newPath, requestTemplate, host, isFilePath);
            allPayloads.addAll(currentPayloads);
        }

        return allPayloads;
    }

    private List<String> generateFilePayloads(List<String> fileNames,
                                              String requestTemplate, String basePath, String host) {
        // 使用新的路径拼接逻辑
        return generatePathBasedPayloads(fileNames, requestTemplate, basePath, host, true);
    }

    // Path类型实现，与File类型使用相同的基础方法但标记为路径处理
    private List<String> generatePathPayloads(List<String> pathSegments,
                                              String requestTemplate, String basePath, String host) {
        // 使用新的路径拼接逻辑
        return generatePathBasedPayloads(pathSegments, requestTemplate, basePath, host, false);
    }

    // FullPath路径清理工具：确保以"/"开头（根目录），去除空格和连续斜杠
    private String cleanFullPath(String fullPath) {
        if (fullPath == null) return "";
        // 1. 去除首尾空格/换行
        String trimmedPath = fullPath.trim();
        // 2. 空路径默认返回根目录"/"
        if (trimmedPath.isEmpty()) {
            return "/";
        }
        // 3. 确保以"/"开头（根目录标识）
        if (!trimmedPath.startsWith("/")) {
            trimmedPath = "/" + trimmedPath;
        }
        // 4. 合并连续斜杠（如"//a//b" → "/a/b"）
        return trimmedPath.replaceAll("/+", "/");
    }

    // FullPath类型入口：为每个FullPath生成五种请求类型（完全忽略模板路径）
    private List<String> generateFullPathPayloads(List<String> fullPaths, String requestTemplate, String host) {
        List<String> allPayloads = new ArrayList<>();

        // 遍历每个FullPath，单独生成请求（不累积，与File/Path类型一致）
        for (String fullPath : fullPaths) {
            // 清理FullPath格式（确保根目录规则）
            String cleanedPath = cleanFullPath(fullPath);
            if (cleanedPath.isEmpty()) continue;

            // 生成五种请求类型，强制使用清理后的FullPath
            List<String> currentPayloads = generateRequestTypesForFullPath(cleanedPath, requestTemplate, host);
            allPayloads.addAll(currentPayloads);
        }

        return allPayloads;
    }

    // 通用路径处理方法，同时支持File和Path类型
    private List<String> generateRequestTypesForPath(String path, String requestTemplate, String host, boolean isFilePath) {

        // 在方法开始时记录使用的路径信息
        callbacks.printOutput("生成路径Payload - 使用路径: " + path + ", 主机: " + host);

        List<String> payloads = new ArrayList<>();
        IRequestInfo reqInfo = null;

        try {
            // 构建HTTP服务信息
            IHttpService httpService = null;
            if (host != null && !host.isEmpty()) {
                String protocol = "http";
                String hostPart = host;
                int port = 80;

                // 从host解析端口和协议
                if (host.startsWith("https://")) {
                    protocol = "https";
                    hostPart = host.substring(8);
                    port = 443;
                } else if (host.startsWith("http://")) {
                    hostPart = host.substring(7);
                }

                if (hostPart.contains(":")) {
                    String[] parts = hostPart.split(":", 2);
                    hostPart = parts[0];
                    try {
                        port = Integer.parseInt(parts[1]);
                    } catch (NumberFormatException e) {
                        // 保留默认端口
                    }
                }

                httpService = helpers.buildHttpService(hostPart, port, protocol.equals("https"));
            }

            // 分析请求
            if (httpService != null) {
                reqInfo = helpers.analyzeRequest(httpService, requestTemplate.getBytes());
            } else {
                reqInfo = helpers.analyzeRequest(requestTemplate.getBytes());
            }
        } catch (Exception e) {
            reqInfo = helpers.analyzeRequest(requestTemplate.getBytes());
            callbacks.printError("构建HTTP服务时出错: " + e.getMessage());
        }

        String method = reqInfo != null ? reqInfo.getMethod() : "GET";

        // 1. GET请求 - 只修改路径，不带参数
        String getRequest = modifyRequestTemplate(
                requestTemplate,
                "GET",
                path,
                "",
                "", // GET请求不需要Content-Type
                host,
                false // 非multipart不需要额外换行
        );
        payloads.add(getRequest);

        // 2. Form表单 - POST到该路径，空表单
        String formBody = ""; // 空表单
        String formRequest = modifyRequestTemplate(
                requestTemplate,
                "POST",
                path,
                formBody,
                "application/x-www-form-urlencoded",
                host,
                false // 非multipart不需要额外换行
        );
        payloads.add(formRequest);

        // 3. JSON格式 - POST到该路径，空JSON
        String jsonBody = "{}"; // 空JSON对象
        String jsonRequest = modifyRequestTemplate(
                requestTemplate,
                "POST",
                path,
                jsonBody,
                "application/json",
                host,
                false // 非multipart不需要额外换行
        );
        payloads.add(jsonRequest);

        // 4. Multipart表单 - POST到该路径，空multipart
        String boundary = "QRn1u2qw4SzQPvPhVrG1zZ8r1YPexWvH";
        // 修复：确保multipart体格式正确，结尾添加换行
        String multipartBody = "--" + boundary + "--\r\n";
        String multipartRequest = modifyRequestTemplate(
                requestTemplate,
                "POST",
                path,
                multipartBody,
                "multipart/form-data; boundary=" + boundary,
                host,
                true // 需要确保正确换行
        );
        payloads.add(multipartRequest);

        // 5. 额外的POST表单请求 - 与2保持一致，空表单
        String extraFormRequest = modifyRequestTemplate(
                requestTemplate,
                "POST",
                path,
                formBody,
                "application/x-www-form-urlencoded",
                host,
                false // 非multipart不需要额外换行
        );
        payloads.add(extraFormRequest);

        return payloads;
    }

    // FullPath类型专用：生成五种请求类型（完全忽略模板路径，强制使用根目录路径）
    private List<String> generateRequestTypesForFullPath(String fullPath, String requestTemplate, String host) {
        List<String> payloads = new ArrayList<>();
        IRequestInfo reqInfo = null;

        try {
            // 构建HTTP服务（仅解析Host/端口，与路径无关）
            IHttpService httpService = null;
            if (host != null && !host.isEmpty()) {
                String protocol = "http";
                String hostPart = host;
                int port = 80;

                // 从Host解析协议和端口（兼容带http/https的Host格式）
                if (host.startsWith("https://")) {
                    protocol = "https";
                    hostPart = host.substring(8);
                    port = 443;
                } else if (host.startsWith("http://")) {
                    hostPart = host.substring(7);
                }

                // 解析带端口的Host（如"xxx.com:8080"）
                if (hostPart.contains(":")) {
                    String[] parts = hostPart.split(":", 2);
                    hostPart = parts[0];
                    try {
                        port = Integer.parseInt(parts[1]);
                    } catch (NumberFormatException e) {
                        // 端口解析失败则保留默认端口
                    }
                }

                httpService = helpers.buildHttpService(hostPart, port, protocol.equals("https"));
            }

            // 分析请求模板（仅用于获取原始方法，路径会被FullPath覆盖）
            if (httpService != null) {
                reqInfo = helpers.analyzeRequest(httpService, requestTemplate.getBytes());
            } else {
                reqInfo = helpers.analyzeRequest(requestTemplate.getBytes());
            }
        } catch (Exception e) {
            reqInfo = helpers.analyzeRequest(requestTemplate.getBytes());
            callbacks.printError("构建HTTP服务时出错: " + e.getMessage());
        }

        // 固定使用POST方法
        String method = "POST";

        // 1. GET请求：仅使用FullPath，不带参数
        String getRequest = modifyRequestTemplate(
                requestTemplate,
                "GET",
                fullPath,
                "",
                "", // GET无需Content-Type
                host,
                false
        );
        payloads.add(getRequest);

        // 2. Form表单：POST到FullPath，空表单
        String formBody = "";
        String formRequest = modifyRequestTemplate(
                requestTemplate,
                method,
                fullPath,
                formBody,
                "application/x-www-form-urlencoded",
                host,
                false
        );
        payloads.add(formRequest);

        // 3. JSON格式：POST到FullPath，空JSON
        String jsonBody = "{}";
        String jsonRequest = modifyRequestTemplate(
                requestTemplate,
                method,
                fullPath,
                jsonBody,
                "application/json",
                host,
                false
        );
        payloads.add(jsonRequest);

        // 4. Multipart表单：POST到FullPath，空multipart（确保格式正确）
        String boundary = "QRn1u2qw4SzQPvPhVrG1zZ8r1YPexWvH";
        String multipartBody = "--" + boundary + "--\r\n"; // 结尾必须带换行
        String multipartRequest = modifyRequestTemplate(
                requestTemplate,
                method,
                fullPath,
                multipartBody,
                "multipart/form-data; boundary=" + boundary,
                host,
                true // 确保multipart结尾换行
        );
        payloads.add(multipartRequest);

        // 5. 额外Form表单：与2一致，冗余保障
        String extraFormRequest = modifyRequestTemplate(
                requestTemplate,
                method,
                fullPath,
                formBody,
                "application/x-www-form-urlencoded",
                host,
                false
        );
        payloads.add(extraFormRequest);

        return payloads;
    }

    // 为Param类型的参数集合生成五种请求类型
    private List<String> generateRequestTypesForParams(List<Map.Entry<String, String>> paramValues,
                                                       String requestTemplate, String path, String host) {

        // 在方法开始时记录使用的路径信息
        callbacks.printOutput("生成参数Payload - 使用路径: " + path + ", 主机: " + host);

        List<String> payloads = new ArrayList<>();
        IRequestInfo reqInfo = null;

        try {
            // 构建HTTP服务信息
            IHttpService httpService = null;
            if (host != null && !host.isEmpty()) {
                String protocol = "http";
                String hostPart = host;
                int port = 80;

                // 从host解析端口和协议
                if (host.startsWith("https://")) {
                    protocol = "https";
                    hostPart = host.substring(8);
                    port = 443;
                } else if (host.startsWith("http://")) {
                    hostPart = host.substring(7);
                }

                if (hostPart.contains(":")) {
                    String[] parts = hostPart.split(":", 2);
                    hostPart = parts[0];
                    try {
                        port = Integer.parseInt(parts[1]);
                    } catch (NumberFormatException e) {
                        // 保留默认端口
                    }
                }

                httpService = helpers.buildHttpService(hostPart, port, protocol.equals("https"));
            }

            // 使用带HTTP服务的方法分析请求
            if (httpService != null) {
                reqInfo = helpers.analyzeRequest(httpService, requestTemplate.getBytes());
            } else {
                reqInfo = helpers.analyzeRequest(requestTemplate.getBytes());
            }
        } catch (Exception e) {
            reqInfo = helpers.analyzeRequest(requestTemplate.getBytes());
            callbacks.printError("构建HTTP服务时出错: " + e.getMessage());
        }


        String method = reqInfo != null ? reqInfo.getMethod() : "GET";

        // 提取原始请求中的参数
        List<String> originalParams = new ArrayList<>();
        if (reqInfo != null) {
            String query = reqInfo.getUrl().getQuery();
            if (query != null && !query.isEmpty()) {
                originalParams.addAll(Arrays.asList(query.split("&")));
            }
        }

        // 1. GET请求 - 所有参数组合到URL中，保留原有参数
        StringBuilder getParams = new StringBuilder();
        // 添加原始参数
        for (int i = 0; i < originalParams.size(); i++) {
            if (i > 0) getParams.append("&");
            getParams.append(originalParams.get(i));
        }
        // 添加新生成的参数
        for (Map.Entry<String, String> entry : paramValues) {
            if (getParams.length() > 0) {
                getParams.append("&");
            }
            getParams.append(entry.getKey()).append("=").append(entry.getValue());
        }

        String getUrl = path;
        if (getParams.length() > 0) {
            getUrl += (path.contains("?") ? "&" : "?") + getParams.toString();
        }

        String getRequest = modifyRequestTemplate(
                requestTemplate,
                method,
                getUrl,
                "",
                "", // GET请求不需要Content-Type
                host,
                false
        );
        payloads.add(getRequest);

        // 2. Form表单 - 保留原始表单参数，添加新参数
        String originalFormBody = "";
        int bodySeparator = requestTemplate.indexOf("\r\n\r\n");
        if (bodySeparator != -1 && bodySeparator + 4 < requestTemplate.length()) {
            originalFormBody = requestTemplate.substring(bodySeparator + 4);
        }

        // 解析原始表单参数
        Map<String, String> originalFormParams = new HashMap<>();
        if (reqInfo != null && reqInfo.getContentType() == IRequestInfo.CONTENT_TYPE_URL_ENCODED) {
            for (String param : originalFormBody.split("&")) {
                String[] keyValue = param.split("=", 2);
                if (keyValue.length == 2) {
                    originalFormParams.put(keyValue[0], keyValue[1]);
                } else if (keyValue.length == 1) {
                    originalFormParams.put(keyValue[0], "");
                }
            }
        }

        // 添加新参数
        for (Map.Entry<String, String> entry : paramValues) {
            originalFormParams.put(entry.getKey(), entry.getValue());
        }

        // 重新构建表单体
        StringBuilder formBody = new StringBuilder();
        for (Iterator<Map.Entry<String, String>> it = originalFormParams.entrySet().iterator(); it.hasNext();) {
            Map.Entry<String, String> entry = it.next();
            formBody.append(entry.getKey()).append("=").append(entry.getValue());
            if (it.hasNext()) {
                formBody.append("&");
            }
        }

        String formRequest = modifyRequestTemplate(
                requestTemplate,
                "POST",
                path,
                formBody.toString(),
                "application/x-www-form-urlencoded",
                host,
                false
        );
        payloads.add(formRequest);

        // 3. JSON格式 - 保留原始JSON结构，添加新参数
        StringBuilder jsonBody = new StringBuilder();
        String originalJsonBody = originalFormBody;
        if (reqInfo != null && reqInfo.getContentType() == IRequestInfo.CONTENT_TYPE_JSON && !originalJsonBody.isEmpty()) {
            jsonBody.append(originalJsonBody);
            if (jsonBody.charAt(jsonBody.length() - 1) == '}') {
                jsonBody.setLength(jsonBody.length() - 1);
                if (jsonBody.length() > 0 && jsonBody.charAt(jsonBody.length() - 1) != '{') {
                    jsonBody.append(",");
                }
            }
        } else {
            jsonBody.append("{");
        }

        // 添加新参数
        boolean firstParam = (jsonBody.length() == 1 && jsonBody.charAt(0) == '{');
        for (Map.Entry<String, String> entry : paramValues) {
            if (!firstParam) {
                jsonBody.append(",");
            }
            jsonBody.append("\"").append(entry.getKey()).append("\":\"").append(entry.getValue()).append("\"");
            firstParam = false;
        }

        if (jsonBody.charAt(jsonBody.length() - 1) != '}') {
            jsonBody.append("}");
        }

        String jsonRequest = modifyRequestTemplate(
                requestTemplate,
                "POST",
                path,
                jsonBody.toString(),
                "application/json",
                host,
                false
        );
        payloads.add(jsonRequest);

        // 4. Multipart表单 - 保留原始multipart内容，添加新参数
        String boundary = "OuZe0djZj0XzC4teeqFHArUVmLcUkkAf";
        StringBuilder multipartBody = new StringBuilder();

        boolean hasOriginalContent = false;
        if (reqInfo != null && reqInfo.getContentType() == IRequestInfo.CONTENT_TYPE_MULTIPART && !originalFormBody.isEmpty()) {
            multipartBody.append(originalFormBody);
            hasOriginalContent = true;

            // 移除原始内容中可能的结束边界，以便正确添加新内容
            if (multipartBody.toString().endsWith("--" + boundary + "--\r\n")) {
                int endIndex = multipartBody.length() - ("--" + boundary + "--\r\n").length();
                multipartBody.setLength(endIndex);
            } else if (multipartBody.toString().endsWith("--" + boundary + "--")) {
                int endIndex = multipartBody.length() - ("--" + boundary + "--").length();
                multipartBody.setLength(endIndex);
            }
        }

        // 添加新参数，确保正确的格式和分隔
        for (Map.Entry<String, String> entry : paramValues) {
            // 如果有原始内容，先添加一个换行分隔
            if (multipartBody.length() > 0) {
                multipartBody.append("\r\n");
            }
            multipartBody.append("--").append(boundary).append("\r\n")
                    .append("Content-Disposition: form-data; name=\"").append(entry.getKey()).append("\"\r\n\r\n")
                    .append(entry.getValue());
        }

        // 添加结束边界，确保正确换行
        if (multipartBody.length() > 0) {
            multipartBody.append("\r\n--").append(boundary).append("--\r\n");
        } else {
            // 如果没有内容，直接添加空的结束边界并确保结尾有换行
            multipartBody.append("--").append(boundary).append("--\r\n");
        }

        String multipartRequest = modifyRequestTemplate(
                requestTemplate,
                "POST",
                path,
                multipartBody.toString(),
                "multipart/form-data; boundary=" + boundary,
                host,
                false
        );
        payloads.add(multipartRequest);

        // 5. XML格式 - 保留原始XML结构，添加新参数
        String originalXmlBody = originalFormBody;
        StringBuilder xmlBody = new StringBuilder();
        boolean hasRootElement = false;

        if (reqInfo != null && reqInfo.getContentType() == IRequestInfo.CONTENT_TYPE_XML && !originalXmlBody.isEmpty()) {
            xmlBody.append(originalXmlBody);
            hasRootElement = true;

            if (xmlBody.toString().trim().startsWith("<") &&
                    xmlBody.toString().trim().endsWith(">") &&
                    !xmlBody.toString().trim().startsWith("<?xml")) {
                int firstClose = xmlBody.indexOf(">");
                if (firstClose != -1) {
                    String firstTag = xmlBody.substring(1, firstClose).split(" ")[0];
                    if (xmlBody.toString().contains("</" + firstTag + ">")) {
                        int rootEndIndex = xmlBody.lastIndexOf("</" + firstTag + ">");
                        if (rootEndIndex != -1) {
                            String contentBeforeRootEnd = xmlBody.substring(0, rootEndIndex);
                            String rootEndTag = xmlBody.substring(rootEndIndex);
                            xmlBody.setLength(0);
                            xmlBody.append(contentBeforeRootEnd);

                            for (Map.Entry<String, String> entry : paramValues) {
                                xmlBody.append("<").append(entry.getKey()).append(">")
                                        .append(entry.getValue())
                                        .append("</").append(entry.getKey()).append(">");
                            }

                            xmlBody.append(rootEndTag);
                        }
                    }
                }
            }
        }

        if (!hasRootElement) {
            for (Map.Entry<String, String> entry : paramValues) {
                xmlBody.append("<").append(entry.getKey()).append(">")
                        .append(entry.getValue())
                        .append("</").append(entry.getKey()).append(">");
            }
        }

        String xmlRequest = modifyRequestTemplate(
                requestTemplate,
                "POST",
                path,
                xmlBody.toString(),
                "application/xml",
                host,
                false
        );
        payloads.add(xmlRequest);

        return payloads;
    }

    // 修改请求模板的核心方法
    private String modifyRequestTemplate(String template, String method, String path,
                                         String body, String contentType, String host,
                                         boolean ensureTrailingNewline) {
        // 1. 修改请求行（方法和路径）
        String modifiedTemplate = template.replaceFirst("^[A-Z]+\\s+[^\\s]+", method + " " + path);

        // 2. 处理Host头
        if (host != null && !host.isEmpty()) {
            String hostWithoutProtocol = host.replaceAll("^https?://", "");

            Pattern hostPattern = Pattern.compile("(?im)^Host:\\s*.*$");
            Matcher hostMatcher = hostPattern.matcher(modifiedTemplate);

            if (hostMatcher.find()) {
                modifiedTemplate = hostMatcher.replaceFirst("Host: " + hostWithoutProtocol);
            } else {
                int emptyLineIndex = modifiedTemplate.indexOf("\r\n\r\n");
                if (emptyLineIndex != -1) {
                    modifiedTemplate = modifiedTemplate.substring(0, emptyLineIndex) +
                            "\r\nHost: " + hostWithoutProtocol +
                            modifiedTemplate.substring(emptyLineIndex);
                } else {
                    modifiedTemplate += "\r\nHost: " + hostWithoutProtocol;
                }
            }
        }

        // 3. 处理Content-Type
        if (contentType != null && !contentType.isEmpty()) {
            if (modifiedTemplate.contains("Content-Type:")) {
                modifiedTemplate = modifiedTemplate.replaceFirst(
                        "(?m)^Content-Type:.*$",
                        "Content-Type: " + contentType
                );
            } else {
                int hostIndex = modifiedTemplate.indexOf("Host:");
                if (hostIndex != -1) {
                    int endOfHostLine = modifiedTemplate.indexOf("\n", hostIndex) + 1;
                    modifiedTemplate = modifiedTemplate.substring(0, endOfHostLine) +
                            "Content-Type: " + contentType + "\r\n" +
                            modifiedTemplate.substring(endOfHostLine);
                }
            }

            // 更新Content-Length，考虑可能的结尾换行
            int contentLength = body.getBytes().length;
            if (modifiedTemplate.contains("Content-Length:")) {
                modifiedTemplate = modifiedTemplate.replaceFirst(
                        "(?m)^Content-Length:.*$",
                        "Content-Length: " + contentLength
                );
            } else {
                int contentTypeIndex = modifiedTemplate.indexOf("Content-Type:");
                if (contentTypeIndex != -1) {
                    int endOfContentTypeLine = modifiedTemplate.indexOf("\n", contentTypeIndex) + 1;
                    modifiedTemplate = modifiedTemplate.substring(0, endOfContentTypeLine) +
                            "Content-Length: " + contentLength + "\r\n" +
                            modifiedTemplate.substring(endOfContentTypeLine);
                }
            }
        } else {
            // 如果没有指定contentType，移除现有Content-Type和Content-Length
            modifiedTemplate = modifiedTemplate.replaceAll("(?m)^Content-Type:.*$", "");
            modifiedTemplate = modifiedTemplate.replaceAll("(?m)^Content-Length:.*$", "");
            // 清理空行
            modifiedTemplate = modifiedTemplate.replaceAll("\r\n\r\n+", "\r\n\r\n");
        }

        // 4. 替换请求体 - 确保请求头和体之间只有一个空行
        // 先移除所有现有的请求体内容
        int bodySeparator = modifiedTemplate.indexOf("\r\n\r\n");
        String headersPart;
        if (bodySeparator != -1) {
            headersPart = modifiedTemplate.substring(0, bodySeparator + 2); // 只保留一个\r\n
        } else {
            // 如果没有找到分隔符，添加一个
            headersPart = modifiedTemplate + "\r\n";
        }

        // 构建新的请求内容： headers + 空行 + body
        String finalRequest = headersPart + "\r\n" + body;

        // 确保最后有一个换行
        if (ensureTrailingNewline && !finalRequest.endsWith("\r\n")) {
            finalRequest += "\r\n";
        }

        return finalRequest;
    }

    // 在类型处理中同时支持File和Path，使用相同逻辑
    private List<String> generatePayloadsByType(String payloadType, List<String> payloadNames,
                                                List<String> payloadValues, // 新增：传递值列表
                                                String valueType, String valueInput, int valueLength,
                                                String requestTemplate, String path, String host) {
        List<String> generatedPayloads = new ArrayList<>();

        // 根据不同类型处理
        if ("File".equals(payloadType) || "Path".equals(payloadType)) {
            // File和Path使用相同的生成逻辑
            if ("File".equals(payloadType)) {
                generatedPayloads.addAll(generateFilePayloads(payloadNames, requestTemplate, path, host));
            } else {
                generatedPayloads.addAll(generatePathPayloads(payloadNames, requestTemplate, path, host));
            }
        } else if ("FullPath".equals(payloadType)) {
            // FullPath类型：完全忽略模板路径，使用根目录路径
            generatedPayloads.addAll(generateFullPathPayloads(payloadNames, requestTemplate, host));
        } else {
            // Param/Value类型：累积式生成
            List<Map.Entry<String, String>> paramValues = new ArrayList<>();
            for (int i = 0; i < payloadNames.size(); i++) {
                String name = payloadNames.get(i);
                String value;

                // 对于Value类型且有指定值的情况，使用指定值
                if ("Value".equals(payloadType) && i < payloadValues.size() &&
                        payloadValues.get(i) != null && !payloadValues.get(i).trim().isEmpty()) {
                    value = payloadValues.get(i).trim();
                } else {
                    // 否则生成随机值
                    value = generateValue(valueType, valueInput, valueLength);
                }

                paramValues.add(new SimpleEntry<>(name, value));
            }
            generatedPayloads.addAll(generateCumulativePayloads(paramValues, requestTemplate, path, host));
        }

        return generatedPayloads;
    }

    private String generateValue(String valueType, String valueInput, int valueLength) {
        if ("random".equals(valueType)) {
            return generateRandomString(valueInput, valueLength);
        } else {
            String[] values = valueInput.split("\n");
            if (values.length == 0) {
                return "";
            }
            return values[new Random().nextInt(values.length)].trim();
        }
    }

    private String cleanAndJoinPath(String basePath, String additionalPath) {
        if (basePath == null) basePath = "";
        if (additionalPath == null) additionalPath = "";

        basePath = basePath.trim();
        additionalPath = additionalPath.trim();

        // 如果附加路径为空，直接返回基础路径
        if (additionalPath.isEmpty()) {
            return basePath.isEmpty() ? "/" : basePath;
        }

        // 处理基础路径
        if (basePath.isEmpty()) {
            basePath = "/";
        }

        // 确保基础路径以/开头
        if (!basePath.startsWith("/")) {
            basePath = "/" + basePath;
        }

        // 处理附加路径
        if (additionalPath.startsWith("/")) {
            additionalPath = additionalPath.substring(1);
        }

        // 合并路径，处理中间的斜杠
        if (basePath.endsWith("/")) {
            return basePath + additionalPath;
        } else {
            return basePath + "/" + additionalPath;
        }
    }

    private class GeneratorTabContent extends JPanel {
        private final IHttpRequestResponse request;
        private final String initialPayloadType;
        private final String initialPayloads;
        private Font buttonFont;

        private JTextField urlField;
        private IMessageEditor requestEditor;
        private JComboBox<String> payloadTypeCombo;
        private JTextField payloadInputField;
        private DefaultTableModel payloadTableModel;
        private JTable payloadTable;
        private JComboBox<String> valueTypeCombo;
        private JTextField valueInputField;
        private JTextField valueLengthField;
        private byte[] currentRequestContent;
        private String requestTemplate;
        private String requestPath;
        private String requestHost;
        private boolean isUpdatingFromUrl = false;
        private Timer templateUpdateTimer;

        public GeneratorTabContent(IHttpRequestResponse request, String payloadType, String payloads) {
            this.request = request;
            this.initialPayloadType = payloadType;
            this.initialPayloads = payloads;
            initializeRequestContent();
            initUpdateTimer();
            initComponents();
            extractRequestTemplate();
        }

        private void initUpdateTimer() {
            templateUpdateTimer = new Timer(300, e -> {
                if (currentRequestContent != null) {
                    extractRequestTemplate();
                }
            });
            templateUpdateTimer.setRepeats(false);
        }

        private void initializeRequestContent() {
            if (request != null && request.getRequest() != null) {
                currentRequestContent = request.getRequest().clone();
            } else {
                String defaultRequest = "GET / HTTP/1.1\r\n" +
                        "Host: localhost\r\n" +
                        "Cache-Control: max-age=0\r\n" +
                        "Sec-Ch-Ua: \"Chromium\";v=\"140\", \"Not;A=Brand\";v=\"24\", \"Google Chrome\";v=\"140\"\r\n" +
                        "Sec-Ch-Ua-Mobile: ?0\r\n" +
                        "Sec-Ch-Ua-Platform: \"Windows\"\r\n" +
                        "Accept-Language: en-US;q=0.9,en;q=0.8\r\n" +
                        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36\r\n" +
                        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\n" +
                        "Sec-Fetch-Site: none\r\n" +
                        "Sec-Fetch-Mode: navigate\r\n" +
                        "Sec-Fetch-User: ?1\r\n" +
                        "Sec-Fetch-Dest: document\r\n" +
                        "Accept-Encoding: gzip, deflate, br\r\n" +
                        "Connection: keep-alive\r\n" +
                        "\r\n";
                currentRequestContent = defaultRequest.getBytes();
            }
        }

        private void initComponents() {
            setLayout(new BorderLayout());
            setBorder(new EmptyBorder(10, 10, 10, 10));

            JSplitPane mainSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
            mainSplit.setDividerLocation(550);
            mainSplit.setResizeWeight(0.55);

            JPanel leftPanel = createLeftPanel();
            JSplitPane rightSplit = createRightPanel();

            mainSplit.setLeftComponent(leftPanel);
            mainSplit.setRightComponent(rightSplit);

            add(mainSplit, BorderLayout.CENTER);
        }

        private void updateRequestHostFromTemplate() {
            if (requestTemplate == null) return;

            Pattern pattern = Pattern.compile("(?im)^Host:\\s*(.*)$");
            Matcher matcher = pattern.matcher(requestTemplate);
            if (matcher.find()) {
                requestHost = matcher.group(1).trim();
            } else {
                requestHost = "localhost";
            }
        }

        private void extractRequestTemplate() {
            if (currentRequestContent == null) return;

            // 直接从当前编辑器内容获取模板
            byte[] editorContent = requestEditor.getMessage();
            if (editorContent != null) {
                requestTemplate = new String(editorContent);
            } else {
                requestTemplate = new String(currentRequestContent);
            }

            // 关键修改：直接从请求行提取路径，而不是依赖analyzeRequest
            extractPathAndHostFromTemplate();
        }

        private void extractPathAndHostFromTemplate() {
            if (requestTemplate == null || requestTemplate.trim().isEmpty()) {
                requestPath = "/";
                requestHost = "localhost";
                return;
            }

            try {
                // 1. 从请求行提取路径
                String[] lines = requestTemplate.split("\r\n");
                if (lines.length > 0) {
                    String requestLine = lines[0];
                    // 解析请求行: METHOD PATH PROTOCOL
                    String[] parts = requestLine.split("\\s+");
                    if (parts.length >= 2) {
                        String pathPart = parts[1];
                        // 提取路径（去除协议和主机部分）
                        if (pathPart.startsWith("http")) {
                            try {
                                URL url = new URL(pathPart);
                                requestPath = url.getPath();
                                if (url.getQuery() != null) {
                                    requestPath += "?" + url.getQuery();
                                }
                            } catch (MalformedURLException e) {
                                // 如果不是完整URL，直接使用
                                requestPath = pathPart;
                            }
                        } else {
                            requestPath = pathPart;
                        }

                        // 确保路径不为空
                        if (requestPath == null || requestPath.isEmpty()) {
                            requestPath = "/";
                        }
                    } else {
                        requestPath = "/";
                    }
                } else {
                    requestPath = "/";
                }

                // 2. 从Host头提取主机信息
                requestHost = "localhost"; // 默认值
                for (String line : lines) {
                    if (line.toLowerCase().startsWith("host:")) {
                        String hostValue = line.substring(5).trim();
                        requestHost = hostValue;
                        break;
                    }
                }

                // 3. 可选：更新URL字段显示（不影响生成逻辑）
                updateUrlFieldDisplay();

            } catch (Exception e) {
                requestPath = "/";
                requestHost = "localhost";
                callbacks.printError("解析请求模板错误: " + e.getMessage());
            }
        }

        private void updateUrlFieldDisplay() {
            try {
                String displayUrl = "http://" + requestHost + requestPath;
                updateUrlFieldWithoutTrigger(displayUrl);
            } catch (Exception e) {
                // 忽略显示更新错误
            }
        }

        private void updateUrlFieldWithoutTrigger(String url) {
            ActionListener[] listeners = urlField.getActionListeners();
            for (ActionListener listener : listeners) {
                urlField.removeActionListener(listener);
            }

            urlField.setText(url);

            for (ActionListener listener : listeners) {
                urlField.addActionListener(listener);
            }
        }

        private void parseUrlFromField() {
            try {
                String urlText = urlField.getText().trim();
                if (!urlText.isEmpty()) {
                    URL url = new URL(urlText);
                    requestPath = url.getPath();
                    if (requestPath == null || requestPath.isEmpty()) {
                        requestPath = "/";
                    }

                    String query = url.getQuery();
                    if (query != null && !query.isEmpty()) {
                        requestPath += "?" + query;
                    }

                    requestHost = url.getHost();
                    if (url.getPort() != -1) {
                        requestHost += ":" + url.getPort();
                    }
                }
            } catch (MalformedURLException e) {
                requestPath = "/";
                requestHost = "localhost";
            }
        }

        private void updateTemplateFromUrl() {
            // 完全禁用URL更新模板的功能
            // 保留这个方法但不执行任何操作，或者可以显示提示信息
            // JOptionPane.showMessageDialog(this, "URL修改功能已禁用，请直接在请求模板中修改", "提示", JOptionPane.INFORMATION_MESSAGE);

            // 或者可以选择性地只更新显示而不影响实际模板
            String urlText = urlField.getText().trim();
            if (urlText.isEmpty()) return;

            try {
                URL url = new URL(urlText);
                // 只更新显示，不修改实际请求模板
                // 这样可以保持URL输入框的显示功能，但不影响生成逻辑
            } catch (MalformedURLException e) {
                // 忽略URL格式错误，因为URL不再影响模板
            }
        }

        private JPanel createLeftPanel() {

            JPanel panel = new JPanel(new BorderLayout(0, 10));
            panel.setBorder(new EmptyBorder(5, 5, 5, 5));

            JPanel urlPanel = new JPanel(new BorderLayout(10, 0));
            JLabel urlLabel = new JLabel("URL:");
            urlField = new JTextField();

            // 保持URL字段可编辑，但添加提示信息
            urlField.setEditable(true);
            urlField.setToolTipText("URL输入框（功能开发中，当前仅用于显示）");

            // 添加焦点监听器，在获得焦点时显示提示
            urlField.addFocusListener(new FocusAdapter() {
                @Override
                public void focusGained(FocusEvent e) {
                    // 可选：在获得焦点时显示提示
                    urlField.setToolTipText("URL输入框（功能开发中，修改请求请直接编辑下方模板）");
                }

                @Override
                public void focusLost(FocusEvent e) {
                    if (!e.isTemporary()) {
                        // 在失去焦点时恢复原始提示
                        urlField.setToolTipText("URL输入框（功能开发中，当前仅用于显示）");

                        // 可选：如果用户输入了内容，可以显示提示但不执行操作
                        String userInput = urlField.getText().trim();
                        if (!userInput.isEmpty() && !userInput.equals(getCurrentDisplayUrl())) {
                            // 显示提示信息但不修改模板
                            showUrlFeatureInfo();
                            // 恢复原来的显示URL
                            updateUrlFieldDisplay();
                        }
                    }
                }
            });

            // 添加按键监听，在用户按Enter时显示提示
            urlField.addActionListener(e -> {
                String userInput = urlField.getText().trim();
                if (!userInput.isEmpty() && !userInput.equals(getCurrentDisplayUrl())) {
                    showUrlFeatureInfo();
                    // 恢复原来的显示URL
                    updateUrlFieldDisplay();
                }
            });

            // 设置初始URL显示
            if (request != null && request.getRequest() != null) {
                IRequestInfo reqInfo = helpers.analyzeRequest(request);
                urlField.setText(reqInfo.getUrl().toString());
            } else {
                urlField.setText("http://localhost/");
            }

            JButton generateBtn = new JButton("Generate");
            generateBtn.addActionListener(e -> handleGenerate());

            this.buttonFont = generateBtn.getFont();
            generateBtn.setPreferredSize(UNIFORM_BUTTON_SIZE);
            generateBtn.setMinimumSize(UNIFORM_BUTTON_SIZE);
            generateBtn.setMaximumSize(UNIFORM_BUTTON_SIZE);
            generateBtn.setFont(buttonFont);
            generateBtn.setHorizontalAlignment(SwingConstants.CENTER);
            generateBtn.setMargin(new Insets(2, 5, 2, 5));

            urlPanel.add(urlLabel, BorderLayout.WEST);
            urlPanel.add(urlField, BorderLayout.CENTER);
            urlPanel.add(generateBtn, BorderLayout.EAST);

            JPanel requestPanel = new JPanel(new BorderLayout(0, 5));
            JLabel requestLabel = new JLabel("Request Template");
            requestLabel.setFont(new Font(requestLabel.getFont().getName(), Font.BOLD, 14));

            requestEditor = callbacks.createMessageEditor(new IMessageEditorController() {
                @Override
                public IHttpService getHttpService() {
                    return request != null ? request.getHttpService() : null;
                }

                @Override
                public byte[] getRequest() {
                    return currentRequestContent;
                }

                @Override
                public byte[] getResponse() {
                    return request != null ? request.getResponse() : null;
                }
            }, true);

            Component editorComponent = requestEditor.getComponent();
            editorComponent.addFocusListener(new FocusAdapter() {
                @Override
                public void focusLost(FocusEvent e) {
                    if (!e.isTemporary() && !isUpdatingFromUrl) {
                        byte[] newContent = requestEditor.getMessage();
                        if (newContent != null && !Arrays.equals(newContent, currentRequestContent)) {
                            currentRequestContent = newContent.clone();
                            extractRequestTemplate();
                        }
                    }
                }
            });

            editorComponent.addKeyListener(new KeyAdapter() {
                @Override
                public void keyReleased(KeyEvent e) {
                    if (e.isControlDown() && e.getKeyCode() == KeyEvent.VK_S) {
                        byte[] newContent = requestEditor.getMessage();
                        if (newContent != null && !Arrays.equals(newContent, currentRequestContent)) {
                            currentRequestContent = newContent.clone();
                            extractRequestTemplate();
                        }
                    } else {
                        byte[] newContent = requestEditor.getMessage();
                        if (newContent != null && !Arrays.equals(newContent, currentRequestContent)) {
                            currentRequestContent = newContent.clone();
                            templateUpdateTimer.restart();
                        }
                    }
                }
            });

            if (editorComponent instanceof JComponent) {
                JPopupMenu popupMenu = createRequestPopupMenu();
                ((JComponent) editorComponent).setComponentPopupMenu(popupMenu);
            }

            editorComponent.addMouseListener(new MouseAdapter() {
                @Override
                public void mousePressed(MouseEvent e) {
                    if (e.isPopupTrigger()) {
                        showPopupMenu(e);
                    }
                }

                @Override
                public void mouseReleased(MouseEvent e) {
                    if (e.isPopupTrigger()) {
                        showPopupMenu(e);
                    }
                }

                private void showPopupMenu(MouseEvent e) {
                    JPopupMenu popup = createRequestPopupMenu();
                    popup.show(e.getComponent(), e.getX(), e.getY());
                }
            });

            requestEditor.setMessage(currentRequestContent, true);

            requestPanel.add(requestLabel, BorderLayout.NORTH);
            requestPanel.add(editorComponent, BorderLayout.CENTER);

            panel.add(urlPanel, BorderLayout.NORTH);
            panel.add(requestPanel, BorderLayout.CENTER);

            return panel;
        }

        // 获取当前显示URL的方法
        private String getCurrentDisplayUrl() {
            return urlField.getText();
        }

        // 显示URL功能提示信息
        private void showUrlFeatureInfo() {
            // 使用更友好的提示方式
            JOptionPane.showMessageDialog(this,
                    "URL修改功能正在开发中\n\n" +
                            "当前请直接编辑下方的请求模板来修改：\n" +
                            "- 修改请求行中的路径\n" +
                            "- 修改Host头中的域名\n" +
                            "- 添加或删除请求头\n\n" +
                            "URL输入框将在后续版本中支持自动更新模板功能。",
                    "功能提示",
                    JOptionPane.INFORMATION_MESSAGE);
        }

        private JPopupMenu createRequestPopupMenu() {
            JPopupMenu popup = new JPopupMenu();

            JMenuItem copyItem = new JMenuItem("Copy");
            copyItem.addActionListener(e -> {
                byte[] selectedData = requestEditor.getSelectedData();
                if (selectedData != null && selectedData.length > 0) {
                    String selectedText = new String(selectedData);
                    Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
                    clipboard.setContents(new StringSelection(selectedText), null);
                }
            });

            JMenuItem cutItem = new JMenuItem("Cut");
            cutItem.addActionListener(e -> {
                byte[] selectedData = requestEditor.getSelectedData();
                if (selectedData != null && selectedData.length > 0) {
                    String selectedText = new String(selectedData);
                    Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
                    clipboard.setContents(new StringSelection(selectedText), null);
                    requestEditor.setMessage(new byte[0], true);
                }
            });

            JMenuItem pasteItem = new JMenuItem("Paste");
            pasteItem.addActionListener(e -> {
                try {
                    Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
                    String data = (String) clipboard.getData(DataFlavor.stringFlavor);
                    if (data != null && !data.isEmpty()) {
                        requestEditor.setMessage(data.getBytes(), true);
                    }
                } catch (Exception ignored) {}
            });

            JMenuItem clearItem = new JMenuItem("Clear");
            clearItem.addActionListener(e -> {
                requestEditor.setMessage(new byte[0], true);
            });

            JMenuItem updateTemplateItem = new JMenuItem("Update Template");
            updateTemplateItem.addActionListener(e -> {
                byte[] newContent = requestEditor.getMessage();
                if (newContent != null && !Arrays.equals(newContent, currentRequestContent)) {
                    currentRequestContent = newContent.clone();
                    extractRequestTemplate();
                }
            });

            Dimension menuItemSize = new Dimension(100, 25);
            copyItem.setPreferredSize(menuItemSize);
            cutItem.setPreferredSize(menuItemSize);
            pasteItem.setPreferredSize(menuItemSize);
            clearItem.setPreferredSize(menuItemSize);
            updateTemplateItem.setPreferredSize(menuItemSize);

            popup.add(copyItem);
            popup.add(cutItem);
            popup.add(pasteItem);
            popup.addSeparator();
            popup.add(clearItem);
            popup.addSeparator();
            popup.add(updateTemplateItem);

            return popup;
        }

        private JSplitPane createRightPanel() {
            JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
            splitPane.setDividerLocation(300);
            splitPane.setResizeWeight(0.8);

            JPanel payloadPanel = new JPanel(new BorderLayout(0, 5));
            payloadPanel.setBorder(new EmptyBorder(5, 5, 5, 5));
            JLabel payloadLabel = new JLabel("Payload");
            payloadLabel.setFont(new Font(payloadLabel.getFont().getName(), Font.BOLD, 14));

            JPanel payloadMainContainer = new JPanel(new BorderLayout(5, 0));

            JPanel inputAndTableContainer = new JPanel(new BorderLayout());
            inputAndTableContainer.setPreferredSize(new Dimension(0, 0));

            JPanel payloadInputContainer = new JPanel(new GridBagLayout());
            payloadInputContainer.setBorder(new EmptyBorder(0, 0, 5, 0));
            payloadInputContainer.setMaximumSize(new Dimension(Integer.MAX_VALUE, 80));
            GridBagConstraints gbc = new GridBagConstraints();
            gbc.insets = new Insets(2, 2, 2, 2);
            gbc.anchor = GridBagConstraints.WEST;
            gbc.fill = GridBagConstraints.HORIZONTAL;
            gbc.gridx = 0;
            gbc.gridy = 0;
            gbc.weightx = 0;

            JLabel payloadTypeLabel = new JLabel("Type:");
            payloadTypeLabel.setPreferredSize(new Dimension(60, 24));
            payloadInputContainer.add(payloadTypeLabel, gbc);

            gbc.gridx = 1;
            gbc.weightx = 1;
            payloadTypeCombo = new JComboBox<>(PAYLOAD_TYPES);
            if (initialPayloadType != null) {
                payloadTypeCombo.setSelectedItem(initialPayloadType);
            }
            payloadTypeCombo.setPreferredSize(new Dimension(0, 24));
            payloadTypeCombo.setMaximumSize(new Dimension(Integer.MAX_VALUE, 24));
            payloadInputContainer.add(payloadTypeCombo, gbc);

            // 添加类型切换监听器，实现自动清空和表格列调整功能
            payloadTypeCombo.addActionListener(e -> {
                String selectedType = (String) payloadTypeCombo.getSelectedItem();

                // 清空输入框
                payloadInputField.setText("");

                // 根据类型调整表格列
                if ("Value".equals(selectedType)) {
                    // 确保Value类型有两列
                    if (payloadTableModel.getColumnCount() != 2) {
                        // 保存现有数据
                        List<String> existingNames = new ArrayList<>();
                        for (int i = 0; i < payloadTableModel.getRowCount(); i++) {
                            Object value = payloadTableModel.getValueAt(i, 0);
                            if (value != null) {
                                existingNames.add(value.toString());
                            }
                        }

                        // 重新创建表格模型
                        payloadTableModel = new DefaultTableModel();
                        payloadTableModel.addColumn("Name");
                        payloadTableModel.addColumn("Value");

                        // 恢复数据
                        for (String name : existingNames) {
                            payloadTableModel.addRow(new String[]{name, ""});
                        }

                        // 更新表格
                        payloadTable.setModel(payloadTableModel);
                    }
                } else {
                    // 其他类型只需要一列
                    if (payloadTableModel.getColumnCount() != 1) {
                        // 保存现有名称列数据
                        List<String> existingNames = new ArrayList<>();
                        for (int i = 0; i < payloadTableModel.getRowCount(); i++) {
                            Object value = payloadTableModel.getValueAt(i, 0);
                            if (value != null) {
                                existingNames.add(value.toString());
                            }
                        }

                        // 重新创建表格模型
                        payloadTableModel = new DefaultTableModel();
                        payloadTableModel.addColumn("Name");

                        // 恢复数据
                        for (String name : existingNames) {
                            payloadTableModel.addRow(new String[]{name});
                        }

                        // 更新表格
                        payloadTable.setModel(payloadTableModel);
                    }
                }

                // 根据新类型设置默认提示
                if (selectedType != null) {
                    switch (selectedType) {
                        case "Param":
                            payloadInputField.setToolTipText("参数名 (按Enter添加)");
                            break;
                        case "File":
                            payloadInputField.setToolTipText("文件名 (按Enter添加)");
                            break;
                        case "Path":
                            payloadInputField.setToolTipText("路径段 (按Enter添加)");
                            break;
                        case "FullPath":
                            payloadInputField.setToolTipText("完整路径 (按Enter添加)");
                            break;
                        case "Value":
                            payloadInputField.setToolTipText("名称=值 (按Enter添加，例如: id=123)");
                            break;
                    }
                }
            });

            gbc.gridx = 0;
            gbc.gridy = 1;
            gbc.weightx = 0;
            JLabel payloadInputLabel = new JLabel("Input:");
            payloadInputLabel.setPreferredSize(new Dimension(60, 24));
            payloadInputContainer.add(payloadInputLabel, gbc);

            gbc.gridx = 1;
            gbc.weightx = 1;
            payloadInputField = new JTextField();
            payloadInputField.setToolTipText("Payload input (press Enter to add)");
            payloadInputField.setPreferredSize(new Dimension(0, 24));
            payloadInputField.setMaximumSize(new Dimension(Integer.MAX_VALUE, 24));
            payloadInputContainer.add(payloadInputField, gbc);

            JPanel tablePanel = new JPanel(new BorderLayout());
            tablePanel.setBorder(new EmptyBorder(5, 0, 0, 0));

            // 初始化表格模型 - 根据初始类型决定列数
            if ("Value".equals(initialPayloadType)) {
                payloadTableModel = new DefaultTableModel();
                payloadTableModel.addColumn("Name");
                payloadTableModel.addColumn("Value");
                if (initialPayloads != null && !initialPayloads.isEmpty()) {
                    String[] parts = initialPayloads.split("=", 2);
                    if (parts.length == 2) {
                        payloadTableModel.addRow(new String[]{parts[0], parts[1]});
                    } else {
                        payloadTableModel.addRow(new String[]{initialPayloads, ""});
                    }
                }
            } else {
                payloadTableModel = new DefaultTableModel();
                payloadTableModel.addColumn("Name");
                if (initialPayloads != null && !initialPayloads.isEmpty()) {
                    payloadTableModel.addRow(new String[]{initialPayloads});
                } else {
                    payloadTableModel.addRow(new String[]{"id"});
                }
            }

            payloadTable = new JTable(payloadTableModel);
            JScrollPane tableScroll = new JScrollPane(payloadTable);
            tableScroll.setPreferredSize(new Dimension(0, 200));
            tableScroll.setMaximumSize(new Dimension(Integer.MAX_VALUE, Integer.MAX_VALUE));
            tablePanel.add(tableScroll, BorderLayout.CENTER);

            inputAndTableContainer.add(payloadInputContainer, BorderLayout.NORTH);
            inputAndTableContainer.add(tablePanel, BorderLayout.CENTER);

            JPanel payloadBtnPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 0, 5));
            payloadBtnPanel.setPreferredSize(new Dimension(100, 130));
            payloadBtnPanel.setMinimumSize(new Dimension(100, 130));
            payloadBtnPanel.setMaximumSize(new Dimension(100, 130));

            JPanel btnVerticalContainer = new JPanel();
            btnVerticalContainer.setLayout(new BoxLayout(btnVerticalContainer, BoxLayout.Y_AXIS));
            btnVerticalContainer.setAlignmentX(Component.CENTER_ALIGNMENT);

            JButton addBtn = new JButton("Add");
            JButton removeBtn = new JButton("Remove");
            JButton pasteBtn = new JButton("Paste");
            JButton clearBtn = new JButton("Clear");

            addBtn.setPreferredSize(UNIFORM_BUTTON_SIZE);
            removeBtn.setPreferredSize(UNIFORM_BUTTON_SIZE);
            pasteBtn.setPreferredSize(UNIFORM_BUTTON_SIZE);
            clearBtn.setPreferredSize(UNIFORM_BUTTON_SIZE);

            addBtn.setMinimumSize(UNIFORM_BUTTON_SIZE);
            removeBtn.setMinimumSize(UNIFORM_BUTTON_SIZE);
            pasteBtn.setMinimumSize(UNIFORM_BUTTON_SIZE);
            clearBtn.setMinimumSize(UNIFORM_BUTTON_SIZE);

            addBtn.setMaximumSize(UNIFORM_BUTTON_SIZE);
            removeBtn.setMaximumSize(UNIFORM_BUTTON_SIZE);
            pasteBtn.setMaximumSize(UNIFORM_BUTTON_SIZE);
            clearBtn.setMaximumSize(UNIFORM_BUTTON_SIZE);

            addBtn.setFont(buttonFont);
            removeBtn.setFont(buttonFont);
            pasteBtn.setFont(buttonFont);
            clearBtn.setFont(buttonFont);

            addBtn.setHorizontalAlignment(SwingConstants.CENTER);
            removeBtn.setHorizontalAlignment(SwingConstants.CENTER);
            pasteBtn.setHorizontalAlignment(SwingConstants.CENTER);
            clearBtn.setHorizontalAlignment(SwingConstants.CENTER);

            addBtn.setMargin(new Insets(2, 2, 2, 2));
            removeBtn.setMargin(new Insets(2, 2, 2, 2));
            pasteBtn.setMargin(new Insets(2, 2, 2, 2));
            clearBtn.setMargin(new Insets(2, 2, 2, 2));

            btnVerticalContainer.add(addBtn);
            btnVerticalContainer.add(Box.createRigidArea(new Dimension(0, 3)));
            btnVerticalContainer.add(removeBtn);
            btnVerticalContainer.add(Box.createRigidArea(new Dimension(0, 3)));
            btnVerticalContainer.add(pasteBtn);
            btnVerticalContainer.add(Box.createRigidArea(new Dimension(0, 3)));
            btnVerticalContainer.add(clearBtn);

            payloadBtnPanel.add(btnVerticalContainer);

            payloadMainContainer.add(inputAndTableContainer, BorderLayout.CENTER);
            payloadMainContainer.add(payloadBtnPanel, BorderLayout.EAST);

            payloadPanel.add(payloadLabel, BorderLayout.NORTH);
            payloadPanel.add(payloadMainContainer, BorderLayout.CENTER);

            JPanel valuePanel = new JPanel(new BorderLayout(0, 5));
            valuePanel.setBorder(new EmptyBorder(5, 5, 5, 5));
            valuePanel.setMaximumSize(new Dimension(400, 150));
            JLabel valueLabel = new JLabel("Value");
            valueLabel.setFont(new Font(valueLabel.getFont().getName(), Font.BOLD, 14));

            JPanel valueInputPanel = new JPanel(new GridBagLayout());
            GridBagConstraints valueGbc = new GridBagConstraints();
            valueGbc.insets = new Insets(2, 2, 2, 2);
            valueGbc.anchor = GridBagConstraints.WEST;
            valueGbc.fill = GridBagConstraints.HORIZONTAL;
            valueGbc.gridx = 0;
            valueGbc.gridy = 0;
            valueGbc.weightx = 0;

            JLabel valueTypeLabel = new JLabel("Type:");
            valueTypeLabel.setPreferredSize(new Dimension(60, 24));
            valueInputPanel.add(valueTypeLabel, valueGbc);

            valueGbc.gridx = 1;
            valueGbc.weightx = 1;
            valueTypeCombo = new JComboBox<>(VALUE_TYPES);
            valueTypeCombo.setPreferredSize(new Dimension(200, 24));
            valueTypeCombo.setMaximumSize(new Dimension(200, 24));
            valueInputPanel.add(valueTypeCombo, valueGbc);

            valueGbc.gridx = 0;
            valueGbc.gridy = 1;
            valueGbc.weightx = 0;
            JLabel valueInputLabel = new JLabel("Input:");
            valueInputLabel.setPreferredSize(new Dimension(60, 24));
            valueInputPanel.add(valueInputLabel, valueGbc);

            valueGbc.gridx = 1;
            valueGbc.weightx = 1;
            valueInputField = new JTextField("abcdefghijklmnopqrstuvwxyz0123456789");
            valueInputField.setPreferredSize(new Dimension(200, 24));
            valueInputField.setMaximumSize(new Dimension(200, 24));
            valueInputPanel.add(valueInputField, valueGbc);

            valueGbc.gridx = 0;
            valueGbc.gridy = 2;
            valueGbc.weightx = 0;
            JLabel valueLengthLabel = new JLabel("Length:");
            valueLengthLabel.setPreferredSize(new Dimension(60, 24));
            valueInputPanel.add(valueLengthLabel, valueGbc);

            valueGbc.gridx = 1;
            valueGbc.weightx = 1;
            valueLengthField = new JTextField("8");
            valueLengthField.setPreferredSize(new Dimension(200, 24));
            valueLengthField.setMaximumSize(new Dimension(200, 24));
            valueInputPanel.add(valueLengthField, valueGbc);

            valuePanel.add(valueLabel, BorderLayout.NORTH);
            valuePanel.add(valueInputPanel, BorderLayout.CENTER);

            splitPane.setLeftComponent(payloadPanel);
            splitPane.setRightComponent(valuePanel);

            // 添加按钮事件监听器
            addBtn.addActionListener(e -> {
                String text = payloadInputField.getText().trim();
                if (!text.isEmpty()) {
                    addPayloadRow(text);
                    payloadInputField.setText("");
                }
            });

            removeBtn.addActionListener(e -> {
                int selectedRow = payloadTable.getSelectedRow();
                if (selectedRow != -1) {
                    payloadTableModel.removeRow(selectedRow);
                }
            });

            pasteBtn.addActionListener(e -> {
                Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
                try {
                    String data = (String) clipboard.getData(DataFlavor.stringFlavor);
                    if (data != null && !data.isEmpty()) {
                        String[] lines = data.split("\n");
                        for (String line : lines) {
                            addPayloadRow(line.trim());
                        }
                        deduplicateTableData(payloadTableModel);
                    }
                } catch (Exception ignored) {}
            });

            clearBtn.addActionListener(e -> payloadTableModel.setRowCount(0));

            payloadInputField.addActionListener(e -> {
                String text = payloadInputField.getText().trim();
                if (!text.isEmpty()) {
                    addPayloadRow(text);
                    payloadInputField.setText("");
                }
            });

            return splitPane;
        }

        // 添加行数据，支持自动拆分"name=value"格式
        private void addPayloadRow(String text) {
            String selectedType = (String) payloadTypeCombo.getSelectedItem();

            if ("Value".equals(selectedType)) {
                // 对于Value类型，尝试按=拆分
                String[] parts = text.split("=", 2); // 只拆分成两部分
                if (parts.length == 2) {
                    payloadTableModel.addRow(new String[]{parts[0].trim(), parts[1].trim()});
                } else {
                    // 如果没有=，只添加到Name列
                    payloadTableModel.addRow(new String[]{text, ""});
                }
            } else {
                // 其他类型只添加到Name列
                payloadTableModel.addRow(new String[]{text});
            }

            deduplicateTableData(payloadTableModel);
        }

        private void deduplicateTableData(DefaultTableModel model) {
            Set<List<Object>> rowSet = new LinkedHashSet<>();
            int rowCount = model.getRowCount();
            int colCount = model.getColumnCount();

            for (int i = 0; i < rowCount; i++) {
                List<Object> row = new ArrayList<>();
                for (int j = 0; j < colCount; j++) {
                    row.add(model.getValueAt(i, j));
                }
                rowSet.add(row);
            }

            model.setRowCount(0);
            for (List<Object> row : rowSet) {
                model.addRow(row.toArray());
            }
        }

        private void handleGenerate() {
            try {
                // 在生成前确保使用最新的请求内容
                updateCurrentRequestContent();

                // 重新提取路径和主机信息，确保使用最新数据
                extractPathAndHostFromTemplate();

                callbacks.printOutput("开始生成Payload - 路径: " + requestPath + ", 主机: " + requestHost);

                String payloadType = (String) payloadTypeCombo.getSelectedItem();
                if (payloadType == null || payloadType.isEmpty()) {
                    showError("请选择Payload类型");
                    return;
                }

                List<String> payloadNames = new ArrayList<>();
                List<String> payloadValues = new ArrayList<>();

                // 收集表格数据
                for (int i = 0; i < payloadTableModel.getRowCount(); i++) {
                    String name = (String) payloadTableModel.getValueAt(i, 0);
                    if (name == null || name.trim().isEmpty()) {
                        showError("Payload名称不能为空");
                        return;
                    }
                    payloadNames.add(name.trim());

                    if ("Value".equals(payloadType) && payloadTableModel.getColumnCount() > 1) {
                        Object valueObj = payloadTableModel.getValueAt(i, 1);
                        String value = valueObj != null ? valueObj.toString() : "";
                        payloadValues.add(value);
                    }
                }

                if (payloadNames.isEmpty()) {
                    showError("请至少添加一个Payload名称");
                    return;
                }

                // File/Path/FullPath类型不需要值配置
                String valueType = null;
                String valueInput = null;
                int valueLength = 0;

                if (!"File".equals(payloadType) && !"Path".equals(payloadType) && !"FullPath".equals(payloadType)) {
                    valueType = (String) valueTypeCombo.getSelectedItem();
                    valueInput = valueInputField.getText();
                    try {
                        valueLength = Integer.parseInt(valueLengthField.getText().trim());
                        if (valueLength <= 0) {
                            showError("长度必须是正整数");
                            return;
                        }
                    } catch (NumberFormatException e) {
                        showError("请输入有效的长度数值");
                        return;
                    }
                }

                if (requestTemplate == null || requestTemplate.trim().isEmpty()) {
                    showError("请求模板不能为空");
                    return;
                }

                List<String> payloads = generatePayloadsByType(
                        payloadType,
                        payloadNames,
                        payloadValues,
                        valueType,
                        valueInput,
                        valueLength,
                        requestTemplate,
                        requestPath,  // 使用从模板提取的正确路径
                        requestHost   // 使用从模板提取的正确主机
                );

                if (payloads.isEmpty()) {
                    showInfo("未生成任何Payload，请检查配置");
                    return;
                }

                GLOBAL_PAYLOADS.clear();
                GLOBAL_PAYLOADS.addAll(payloads);

                showInfo("成功生成 " + payloads.size() + " 个Payload");
                callbacks.printOutput("Payload生成完成，共生成 " + payloads.size() + " 个请求");

            } catch (Exception e) {
                showError("生成Payload失败: " + e.getMessage() + "\n" +
                        "请检查配置是否正确");
                e.printStackTrace();
            }
        }

        private void showError(String message) {
            JOptionPane.showMessageDialog(this, message, "错误", JOptionPane.ERROR_MESSAGE);
        }

        private void showInfo(String message) {
            JOptionPane.showMessageDialog(this, message, "信息", JOptionPane.INFORMATION_MESSAGE);
        }

        private void updateCurrentRequestContent() {
            byte[] editorContent = requestEditor.getMessage();
            if (editorContent != null && !Arrays.equals(editorContent, currentRequestContent)) {
                currentRequestContent = editorContent.clone();
                extractRequestTemplate();
            }
        }

        @Override
        public void removeNotify() {
            super.removeNotify();
            if (templateUpdateTimer != null) {
                templateUpdateTimer.stop();
            }
        }

        private class StringSelection implements Transferable {
            private final String data;

            public StringSelection(String data) {
                this.data = data;
            }

            public DataFlavor[] getTransferDataFlavors() {
                return new DataFlavor[] { DataFlavor.stringFlavor };
            }

            public boolean isDataFlavorSupported(DataFlavor flavor) {
                return DataFlavor.stringFlavor.equals(flavor);
            }

            public Object getTransferData(DataFlavor flavor) throws UnsupportedFlavorException, IOException {
                if (!DataFlavor.stringFlavor.equals(flavor)) {
                    throw new UnsupportedFlavorException(flavor);
                }
                return data;
            }
        }
    }
}
