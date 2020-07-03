package burp;

import com.ccumming.burp.controller.Controller;
import com.ccumming.burp.controller.IController;
import com.ccumming.burp.view.IView;
import com.ccumming.burp.view.PandaTabView;

public class BurpExtender implements IBurpExtender {

    // TODO these should be set in the UI
    private final String pandaServerIp = "localhost";
    private final int pandaServerPort = 8081;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        // set our extension name
        callbacks.setExtensionName("PANDA HTTP CMP Analysis");

        // build UI
        IView pandaTab = new PandaTabView(callbacks);
        IController controller = new Controller(callbacks);

        pandaTab.registerButtonListener(controller);

        callbacks.addSuiteTab(pandaTab);
    }

}
