package burp.pkey.onescan.common;

import burp.pkey.common.filter.FilterRule;
import burp.pkey.common.filter.TableFilter;
import burp.pkey.common.filter.TableFilterPanel;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;

/**
 * 过滤对话框回调接口适配器
 * <p>
 * Created by vaycore on 2023-04-21.
 */
public class DialogCallbackAdapter implements TableFilterPanel.DialogCallback {


    @Override
    public void onConfirm(ArrayList<FilterRule> filterRules, ArrayList<TableFilter<AbstractTableModel>> filters, String rulesText) {

    }

    @Override
    public void onReset() {

    }

    @Override
    public void onCancel() {

    }
}
