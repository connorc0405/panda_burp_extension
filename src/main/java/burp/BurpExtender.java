package burp;

import com.ccumming.burp.controller.Controller;
import com.ccumming.burp.controller.IController;
import com.ccumming.burp.model.IModel;
import com.ccumming.burp.model.Model;
import com.ccumming.burp.view.AbstractView;
import com.ccumming.burp.view.PandaTabView;

@SuppressWarnings("unused")
public class BurpExtender implements IBurpExtender {

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        callbacks.setExtensionName("PANDA HTTP CMP Analysis");

        // TODO do this in EDT thread?
        IModel model = new Model(callbacks);
        AbstractView pandaTab = new PandaTabView(callbacks);
        IController controller = new Controller(model, pandaTab, callbacks);

        pandaTab.registerButtonListener(controller);

        callbacks.addSuiteTab(pandaTab);
    }

}
