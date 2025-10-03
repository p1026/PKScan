package burp.pkey.onescan.collect;

import burp.pkey.common.utils.JsonUtils;
import burp.pkey.common.utils.StringUtils;
import burp.pkey.onescan.bean.CollectReqResp;
import burp.pkey.onescan.manager.CollectManager;

import java.util.List;

/**
 * Json 字段数据收集
 * <p>
 * Created by vaycore on 2023-12-25.
 */
public class JsonFieldCollect implements CollectManager.ICollectModule {

    @Override
    public String getName() {
        return "JsonField";
    }

    @Override
    public List<String> doCollect(CollectReqResp reqResp) {
        String body = reqResp.getBody();
        if (StringUtils.isEmpty(body)) {
            return null;
        }
        // 检测 JSON 格式
        if (!JsonUtils.hasJson(body)) {
            return null;
        }
        // 提取所有 JSON 字段
        return JsonUtils.findAllKeysByJson(body);
    }
}
