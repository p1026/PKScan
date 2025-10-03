package burp.pkey.common.filter;

import burp.pkey.onescan.common.L;

import java.util.ArrayList;

/**
 * 表过滤规则
 * <p>
 * Created by vaycore on 2023-02-27.
 */
public class FilterRule {

    /**
     * 并且（&&）
     */
    public static final int LOGIC_AND = 1;

    /**
     * 或者（||）
     */
    public static final int LOGIC_OR = 2;

    /**
     * 等于（==）
     */
    public static final int OPERATE_EQUAL = 1;

    /**
     * 不等于（!=）
     */
    public static final int OPERATE_NOT_EQUAL = 2;

    /**
     * 大于（>）
     */
    public static final int OPERATE_GT = 3;

    /**
     * 大于等于（>=）
     */
    public static final int OPERATE_GT_EQUAL = 4;

    /**
     * 小于（<）
     */
    public static final int OPERATE_LT = 5;

    /**
     * 小于等于（<=）
     */
    public static final int OPERATE_LT_EQUAL = 6;

    /**
     * 开头是（startsWith）
     */
    public static final int OPERATE_START = 7;

    /**
     * 开头不是（!startsWith）
     */
    public static final int OPERATE_NOT_START = 8;

    /**
     * 结尾是（endsWith）
     */
    public static final int OPERATE_END = 9;

    /**
     * 结尾不是（!endsWith）
     */
    public static final int OPERATE_NOT_END = 10;

    /**
     * 包含（contains）
     */
    public static final int OPERATE_INCLUDE = 11;

    /**
     * 不包含（!contains）
     */
    public static final int OPERATE_NOT_INCLUDE = 12;

    /**
     * 操作符文本字符串
     */
    public static final String[] OPERATE_ITEMS = {
            L.get("table_filter_rule.please_select"),
            L.get("table_filter_rule.equal_to"),
            L.get("table_filter_rule.not_equal_to"),
            L.get("table_filter_rule.greater_than"),
            L.get("table_filter_rule.greater_than_or_equal_to"),
            L.get("table_filter_rule.less_than"),
            L.get("table_filter_rule.less_than_or_equal_to"),
            L.get("table_filter_rule.starts_with"),
            L.get("table_filter_rule.not_starts_with"),
            L.get("table_filter_rule.ends_with"),
            L.get("table_filter_rule.not_ends_with"),
            L.get("table_filter_rule.contains"),
            L.get("table_filter_rule.not_contains"),
    };

    /**
     * 操作符
     */
    public static final String[] OPERATE_CHAR = {"",
            "==", "!=", ">", ">=", "<", "<=",
            "startsWith", "noStartsWith", "endsWith",
            "noEndsWith", "contains", "noContains"};

    private final int columnIndex;
    private final ArrayList<Item> items;

    public FilterRule(int columnIndex) {
        this.columnIndex = columnIndex;
        this.items = new ArrayList<>();
    }

    public int getColumnIndex() {
        return columnIndex;
    }

    public ArrayList<Item> getItems() {
        return items;
    }

    public void addRule(int logic, int operate, String value) {
        if (!this.items.isEmpty()) {
            if (logic <= 0) {
                throw new IllegalArgumentException("logic is 0");
            }
        }
        if (operate <= 0) {
            throw new IllegalArgumentException("operate is 0");
        }
        if (value == null) {
            value = "";
        }
        this.items.add(new Item(logic, operate, value));
    }

    public static class Item {
        // 逻辑运算符（并且、或者）
        private final int logic;
        // 操作符（等于、不等于、大于、大于等于、小于、小于等于、开头是、开头不是、结尾是、结尾不是、包含、不包含）
        private final int operate;
        private final String value;

        public Item(int logic, int operate, String value) {
            this.logic = logic;
            this.operate = operate;
            this.value = value;
        }

        public int getLogic() {
            return logic;
        }

        public int getOperate() {
            return operate;
        }

        public String getValue() {
            return value;
        }
    }
}
