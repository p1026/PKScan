package burp.pkey.onescan.ui.widget.payloadlist.rule;

import burp.pkey.onescan.common.L;
import burp.pkey.onescan.ui.widget.payloadlist.PayloadRule;

/**
 * 添加前缀
 * <p>
 * Created by vaycore on 2022-09-02.
 */
public class AddPrefix extends PayloadRule {

    @Override
    public String ruleName() {
        return L.get("payload_rule.add_prefix.name");
    }

    @Override
    public int paramCount() {
        return 1;
    }

    @Override
    public String paramName(int index) {
        return L.get("payload_rule.add_prefix.param.prefix");
    }

    @Override
    public String toDescribe() {
        String[] values = getParamValues();
        String paramValue = values[0];
        // 特殊处理 '\r'、'\n' 字符
        if (paramValue.contains("\r")) {
            paramValue = paramValue.replaceAll("\r", "\\\\r");
        }
        if (paramValue.contains("\n")) {
            paramValue = paramValue.replaceAll("\n", "\\\\n");
        }
        return L.get("payload_rule.add_prefix.describe", paramValue);
    }

    @Override
    public String handleProcess(String content) {
        String[] values = getParamValues();
        return values[0] + content;
    }
}
