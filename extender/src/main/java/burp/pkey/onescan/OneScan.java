package burp.pkey.onescan;

import burp.IBurpExtenderCallbacks;
import burp.pkey.common.log.Logger;
import burp.pkey.onescan.common.Config;
import burp.pkey.onescan.common.Constants;
import burp.pkey.onescan.ui.tab.*;

import javax.swing.*;

/**
 * 插件主类
 */
public class OneScan extends JTabbedPane {

    private IBurpExtenderCallbacks mCallbacks;
    private DataBoardTab mDataBoardTab;
    private ConfigPanel mConfigPanel;
    private FingerprintTab mFingerprintTab;
    private CollectPanel collectTab;
    private GeneratorPanel generatorPanel;

    public OneScan(IBurpExtenderCallbacks callbacks) {
        mCallbacks = callbacks;
        loadModule();
        initView();
    }

    private void loadModule() {
        Logger.info(Constants.BANNER);
    }

    private void initView() {
        // 任务面板
        mDataBoardTab = new DataBoardTab();
        addTab(mDataBoardTab.getTitleName(), mDataBoardTab);
        // 配置面板
        mConfigPanel = new ConfigPanel();
        addTab(mConfigPanel.getTitleName(), mConfigPanel);
        // 指纹面板
        mFingerprintTab = new FingerprintTab();
        addTab(mFingerprintTab.getTitleName(), mFingerprintTab);
        // 数据收集面板
        collectTab = new CollectPanel();
        addTab(collectTab.getTitleName(), collectTab);

        //数据生成面板
        generatorPanel = new GeneratorPanel(mCallbacks);
        addTab(generatorPanel.getTabCaption(), generatorPanel.getUiComponent());
    }

    public DataBoardTab getDataBoardTab() {
        return mDataBoardTab;
    }

    public ConfigPanel getConfigPanel() {
        return mConfigPanel;
    }

    public FingerprintTab getFingerprintTab() {
        return mFingerprintTab;
    }

//    public static void main(String[] args) {
//        // 初始化测试模块
//        initTestModule();
//        // 初始化风格
//        initUIStyle();
//        // 创建及设置窗口
//        JFrame frame = new JFrame(Constants.PLUGIN_NAME + " v" + Constants.PLUGIN_VERSION);
//        frame.setSize(1400, 700);
//        // 面板
//        OneScan oneScan = new OneScan();
//        oneScan.getDataBoardTab().testInit();
//        frame.setContentPane(oneScan);
//        // 其它设置
//        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
//        frame.setLocationRelativeTo(null);
//        frame.setVisible(true);
//    }

    private static void initTestModule() {
        Logger.init(true, System.out, System.err);
        Config.init(null);
    }

    private static void initUIStyle() {
        try {
            for (UIManager.LookAndFeelInfo info : UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (Exception e) {
            Logger.error(e.getMessage());
        }
    }

}
