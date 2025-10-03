package burp.pkey.onescan.ui.tab;

import burp.pkey.common.helper.UIHelper;
import burp.pkey.common.layout.HLayout;
import burp.pkey.common.layout.VLayout;
import burp.pkey.common.utils.StringUtils;
import burp.pkey.common.widget.HintTextField;
import burp.pkey.onescan.bean.FpData;
import burp.pkey.onescan.common.L;
import burp.pkey.onescan.common.OnFpColumnModifyListener;
import burp.pkey.onescan.manager.FpManager;
import burp.pkey.onescan.ui.base.BaseTab;
import burp.pkey.onescan.ui.widget.FpColumnManagerWindow;
import burp.pkey.onescan.ui.widget.FpDetailPanel;
import burp.pkey.onescan.ui.widget.FpTable;
import burp.pkey.onescan.ui.widget.FpTestWindow;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.util.*;
import java.util.List;

/**
 * 指纹面板
 * <p>
 * Created by vaycore on 2023-04-21.
 */
public class FingerprintTab extends BaseTab implements ActionListener, KeyListener, OnFpColumnModifyListener {

    private FpTable mFpTable;
    private FpTable mSecondTable;
    private FpTable mThirdTable;
    private FpTable mOneFpTable;
    private JLabel mCountLabel;
    private HintTextField mFpFilterRegexText;
    private FpTestWindow mFpTestWindow;
    private FpColumnManagerWindow mFpColumnManagerWindow;
    private JComboBox<String> mOptionCombo;
    private String mSelectedOption = "One"; // 默认选中第一个表格

    @Override
    protected void initData() {
        FpManager.addOnFpColumnModifyListener(this);
    }

    @Override
    protected void initView() {
        setLayout(new VLayout(0));
        initFpPathPanel();
        initTablePanel(); // 初始化水平排列的三个表格
    }

    @Override
    public String getTitleName() {
        return L.get("tab_name.fingerprint");
    }

    private void initFpPathPanel() {
        JPanel panel = new JPanel(new HLayout(5, true));
        panel.setBorder(new EmptyBorder(0, 5, 0, 5));
        // 指纹存放路径
        JTextField textField = new JTextField(FpManager.getPath(), 35);
        textField.setEditable(false);
        panel.add(textField);
        // 重新加载指纹
        JButton reload = new JButton(L.get("reload"));
        reload.setActionCommand("reload");
        reload.addActionListener(this);
        panel.add(reload);
        // 指纹数量展示
        panel.add(new JLabel(L.get("fingerprint_count")));
        mCountLabel = new JLabel(String.valueOf(FpManager.getCount()));
        panel.add(mCountLabel);
        panel.add(new JPanel(), "1w");

        // 下拉框 - 选择当前操作的表格
        panel.add(new JLabel("当前表格:"));
        mOptionCombo = new JComboBox<>(new String[]{"One", "Two", "Three"});
        mOptionCombo.setSelectedItem(mSelectedOption);
        mOptionCombo.addActionListener(e -> {
            mSelectedOption = (String) mOptionCombo.getSelectedItem();
            // 根据选择切换当前操作表格
            switch (mSelectedOption) {
                case "One":
                    mFpTable = mOneFpTable;
                    break;
                case "Two":
                    mFpTable = mSecondTable;
                    break;
                case "Three":
                    mFpTable = mThirdTable;
                    break;
            }
            doSearch(); // 同步搜索状态
        });
        panel.add(mOptionCombo);

        // 指纹过滤功能
        mFpFilterRegexText = new HintTextField();
        mFpFilterRegexText.setHintText(L.get("regex_filter"));
        mFpFilterRegexText.addKeyListener(this);
        panel.add(mFpFilterRegexText, "1w");
        // 搜索按钮
        JButton search = new JButton(L.get("search"));
        search.setActionCommand("search");
        search.addActionListener(this);
        panel.add(search);
        add(panel, "35px");
    }

//    private void initTablePanel() {
//        JPanel panel = new JPanel(new VLayout(3)); // 外层垂直布局：按钮栏 + 表格区域
//        panel.setBorder(new EmptyBorder(0, 5, 5, 5));
//        panel.add(addButtonPanel()); // 添加按钮栏
//
//        // 创建水平布局的表格容器（从左到右排列三个表格）
//        JPanel tableContainer = new JPanel(new HLayout(5)); // HLayout 确保水平排列
//        tableContainer.setPreferredSize(new Dimension(0, 0)); // 自适应高度
//
//        // 第一个表格（加载指纹数据）
//        mOneFpTable = new FpTable();
//        mOneFpTable.loadData(); // 仅第一个表格加载数据
//        JScrollPane mainScrollPane = new JScrollPane(mOneFpTable);
//        mainScrollPane.setPreferredSize(new Dimension(0, 0)); // 自适应尺寸
//        tableContainer.add(mainScrollPane, "1w"); // 权重1，平均分配水平空间
//
//        // 第二个表格（加载数据）
//        mSecondTable = new FpTable();
//        mSecondTable.loadData();
//        JScrollPane secondScrollPane = new JScrollPane(mSecondTable);
//        secondScrollPane.setPreferredSize(new Dimension(0, 0));
//        tableContainer.add(secondScrollPane, "1w");
//
//        // 第三个表格（不加载数据）
//        mThirdTable = new FpTable();
//        JScrollPane thirdScrollPane = new JScrollPane(mThirdTable);
//        thirdScrollPane.setPreferredSize(new Dimension(0, 0));
//        tableContainer.add(thirdScrollPane, "1w");
//
//        // 初始化当前操作表格为第一个
//        mFpTable = mOneFpTable;
//
//        // 将表格容器添加到主面板
//        panel.add(tableContainer, "1w"); // 占满剩余垂直空间
//        add(panel, "1w");
//    }

    private void initTablePanel() {
        JPanel panel = new JPanel(new VLayout(3));
        panel.setBorder(new EmptyBorder(0, 5, 5, 5));
        panel.add(addButtonPanel());

        JPanel tableContainer = new JPanel(new HLayout(5));
        tableContainer.setPreferredSize(new Dimension(0, 0));

        // 初始化三个表格（不自动加载数据）
        mOneFpTable = new FpTable();
        JScrollPane mainScrollPane = new JScrollPane(mOneFpTable);
        mainScrollPane.setPreferredSize(new Dimension(0, 0));
        tableContainer.add(mainScrollPane, "1w");

        mSecondTable = new FpTable();
        JScrollPane secondScrollPane = new JScrollPane(mSecondTable);
        secondScrollPane.setPreferredSize(new Dimension(0, 0));
        tableContainer.add(secondScrollPane, "1w");

        mThirdTable = new FpTable();
        JScrollPane thirdScrollPane = new JScrollPane(mThirdTable);
        thirdScrollPane.setPreferredSize(new Dimension(0, 0));
        tableContainer.add(thirdScrollPane, "1w");

        mFpTable = mOneFpTable;

        panel.add(tableContainer, "1w");
        add(panel, "1w");

        // 初始化时加载并分配数据
        loadAndDistributeFingerprints();
    }

    // 在 FingerprintTab.java 中修改数据分配方法
    private void loadAndDistributeFingerprints() {
        if (mOneFpTable == null || mSecondTable == null || mThirdTable == null) {
            return;
        }

        List<FpData> allFingerprints = FpManager.getList();
        if (allFingerprints == null) {
            allFingerprints = new ArrayList<>();
        }

        List<FpData> table1Data = new ArrayList<>();
        List<FpData> table2Data = new ArrayList<>();
        List<FpData> table3Data = new ArrayList<>();
        // 新增：记录每个子表格数据对应的全局索引
        List<Integer> table1GlobalIndexes = new ArrayList<>();
        List<Integer> table2GlobalIndexes = new ArrayList<>();
        List<Integer> table3GlobalIndexes = new ArrayList<>();

        for (int globalIndex = 0; globalIndex < allFingerprints.size(); globalIndex++) {
            FpData fp = allFingerprints.get(globalIndex);
            String color = fp.getColor();
            // 按颜色分类并记录全局索引
            if ("red".equals(color)) {
                table1Data.add(fp);
                table1GlobalIndexes.add(globalIndex); // 记录全局索引
            } else if ("gray".equals(color)) {
                table2Data.add(fp);
                table2GlobalIndexes.add(globalIndex);
            } else {
                table3Data.add(fp);
                table3GlobalIndexes.add(globalIndex);
            }
        }

        // 使用带全局索引的方法设置数据
        mOneFpTable.setDataWithGlobalIndexes(table1Data, table1GlobalIndexes);
        mSecondTable.setDataWithGlobalIndexes(table2Data, table2GlobalIndexes);
        mThirdTable.setDataWithGlobalIndexes(table3Data, table3GlobalIndexes);
    }

    // 在 FingerprintTab.java 中修改 getSelectedRowIndex() 为获取全局索引
    private int getSelectedGlobalIndex() {
        int viewRowIndex = mFpTable.getSelectedRow();
        if (viewRowIndex < 0) {
            return -1;
        }
        // 先转换为表格模型的本地索引
        int localRowIndex = mFpTable.convertRowIndexToModel(viewRowIndex);
        // 再获取对应的全局索引
        return mFpTable.getGlobalIndex(localRowIndex);
    }

    // 修正编辑方法的提示和刷新逻辑
    private void doEditItem(FpData data, int globalIndex) {
        if (data == null || globalIndex < 0) {
            return;
        }
        FpData editData = new FpDetailPanel(data).showDialog();
        if (editData != null) {
            FpManager.setItem(globalIndex, editData);
            // 编辑后直接刷新数据
            loadAndDistributeFingerprints();
            refreshCount();
//            UIHelper.showTipsDialog(L.get("fingerprint_edit_success"));
        }
    }

    // 修正删除方法的提示和刷新逻辑
    private void doDeleteItem(FpData data, int globalIndex) {
        if (data == null || globalIndex < 0) {
            return;
        }
        String info = "{" + data.toInfo() + "}";
        int ret = UIHelper.showOkCancelDialog(L.get("fingerprint_delete_hint", info));
        if (ret == 0) {
            FpManager.removeItem(globalIndex);
            // 删除后直接刷新数据
            loadAndDistributeFingerprints();
            refreshCount();
            // 显示删除成功提示
//            UIHelper.showTipsDialog(L.get("fingerprint_delete_success"));
        }
    }

    // 修正重新加载方法的提示
    private void doReload() {
        FpManager.init(FpManager.getPath());
        loadAndDistributeFingerprints();
        refreshCount();
        // 明确显示重新加载成功提示
//        UIHelper.showTipsDialog(L.get("fingerprint_reload_success"));
    }

    private JPanel addButtonPanel() {
        JPanel panel = new JPanel(new HLayout(5, true));
        addButton(panel, L.get("fingerprint_add"), "add-item");
        addButton(panel, L.get("fingerprint_edit"), "edit-item");
        addButton(panel, L.get("fingerprint_delete"), "delete-item");
        addButton(panel, L.get("fingerprint_test"), "test");
        addButton(panel, L.get("fingerprint_clear_cache"), "clear-cache");
        addButton(panel, L.get("fingerprint_column_manager"), "column-manager");
        return panel;
    }

    private void addButton(JPanel panel, String text, String actionCommand) {
        JButton btn = new JButton(text);
        btn.setActionCommand(actionCommand);
        btn.addActionListener(this);
        panel.add(btn);
    }

    @Override
    public void keyTyped(KeyEvent e) {

    }

    @Override
    public void keyPressed(KeyEvent e) {
        if (e.getKeyChar() == KeyEvent.VK_ENTER) {
            doSearch();
        }
    }

    @Override
    public void keyReleased(KeyEvent e) {
        String text = mFpFilterRegexText.getText();
        if (StringUtils.isEmpty(text)) {
            doSearch();
        }
    }

    @Override
    public void onFpColumnModify() {
        // 刷新所有表格的列配置
        if (mOneFpTable != null) mOneFpTable.refreshColumns();
        if (mSecondTable != null) mSecondTable.refreshColumns();
        if (mThirdTable != null) mThirdTable.refreshColumns();
    }

    private void refreshCount() {
        mCountLabel.setText(String.valueOf(FpManager.getCount()));
    }

    public void closeFpTestWindow() {
        if (mFpTestWindow != null) {
            mFpTestWindow.closeWindow();
        }
    }

    public void closeFpColumnManagerWindow() {
        if (mFpColumnManagerWindow != null) {
            mFpColumnManagerWindow.closeWindow();
        }
    }

//    private int getSelectedRowIndex() {
//        int rowIndex = mFpTable.getSelectedRow();
//        if (rowIndex < 0 || rowIndex >= mFpTable.getRowCount()) {
//            return -1;
//        }
//        return mFpTable.convertRowIndexToModel(rowIndex);
//    }

    public void actionPerformed(ActionEvent e) {
        String action = e.getActionCommand();
        int globalIndex = getSelectedGlobalIndex();
        FpData data = (globalIndex >= 0) ? FpManager.getList().get(globalIndex) : null;
        switch (action) {
            case "reload":
                doReload();
                break;
            case "search":
                doSearch();
                break;
            case "add-item":
                doAddItem();
                break;
            case "edit-item":
                doEditItem(data, globalIndex);
                break;
            case "delete-item":
                doDeleteItem(data, globalIndex);
                break;
            case "test":
                doTest();
                break;
            case "clear-cache":
                doClearCache();
                break;
            case "column-manager":
                doColumnManager();
                break;
        }
    }

    private void doSearch() {
        String regex = mFpFilterRegexText.getText();
        RowFilter filter = StringUtils.isEmpty(regex) ? null : RowFilter.regexFilter(regex);
        // 仅对当前选中表格应用过滤
        mFpTable.setRowFilter(filter);
    }

    private void doAddItem() {
        FpData addData = (new FpDetailPanel()).showDialog();
        if (addData != null) {
            mFpTable.addFpData(addData);
            refreshCount();
        }
    }

//    private void doEditItem(FpData data, int rowIndex) {
//        if (data == null) {
//            return;
//        }
//        FpData editData = new FpDetailPanel(data).showDialog();
//        if (editData != null) {
//            mFpTable.setFpData(rowIndex, editData);
//        }
//    }

    private void doTest() {
        if (mFpTestWindow == null) {
            mFpTestWindow = new FpTestWindow();
        }
        mFpTestWindow.showWindow();
    }

    private static void doClearCache() {
        int count = FpManager.getCacheCount();
        if (count == 0) {
            UIHelper.showTipsDialog(L.get("cache_is_empty"));
            return;
        }
        int ret = UIHelper.showOkCancelDialog(L.get("clear_cache_dialog_message", count));
        if (ret == 0) {
            FpManager.clearCache();
            UIHelper.showTipsDialog(L.get("clear_success"));
        }
    }

    private void doColumnManager() {
        if (mFpColumnManagerWindow == null) {
            mFpColumnManagerWindow = new FpColumnManagerWindow();
        }
        mFpColumnManagerWindow.showWindow();
    }

}