package burp;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;

public class BurpExtender implements IBurpExtender
{
    //
    // implement IBurpExtender
    //

    private final String pandaServerIp = "localhost";
    private final int pandaServerPort = 8081;
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        // set our extension name
        callbacks.setExtensionName("PANDA HTTP CMP Analysis");

        // obtain our output and error streams
        PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
        PrintWriter stderr = new PrintWriter(callbacks.getStderr(), true);

        // write a message to our output stream
        stdout.println("Hello output");

        Socket sock = new Socket();
        InetAddress addr;
        try {
            addr = InetAddress.getByName(pandaServerIp);
        } catch (java.net.UnknownHostException e) {
            stderr.println("Oopsie addr error :(");
            return;
        }

        SocketAddress sockAddr = new InetSocketAddress(addr, pandaServerPort);

        try {
            sock.connect(sockAddr);
        } catch (IOException e) {
            stderr.println("Oopsie socket error :(");
            return;
        }

    }
}
