package burp;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.Socket;

public class BurpExtender implements IBurpExtender {
    //
    // implement IBurpExtender
    //

    // provide stdout and stderr to any helper code
    protected static PrintWriter stdout;
    protected static PrintWriter stderr;

    // TODO these should be set in the UI
    private final String pandaServerIp = "localhost";
    private final int pandaServerPort = 8081;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        // set our extension name
        callbacks.setExtensionName("PANDA HTTP CMP Analysis");

        // obtain our output and error streams
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);

        // connect to socket
        Socket pySock;
        try {
            pySock = new Socket(pandaServerIp, pandaServerPort);
        } catch (IOException e) {
            e.printStackTrace(stderr);
            return;
        }

        stdout.println("Connected to socket");

    }
}
