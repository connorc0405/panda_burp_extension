package burp;

import com.google.protobuf.Message;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.ByteBuffer;

public class BurpExtender implements IBurpExtender {
    //
    // implement IBurpExtender
    //

    // provide stdout and stderr to any helper code
    private static PrintWriter stdout;
    private static PrintWriter stderr;

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

        // build UI
        ITab pandaTab = new PandaTabView(callbacks);
        callbacks.addSuiteTab(pandaTab);

//        // connect to socket
//        Socket pySock;
//        try {
//            pySock = new Socket(pandaServerIp, pandaServerPort);
//        } catch (IOException e) {
//            e.printStackTrace(stderr);
//            return;
//        }
//
//        stdout.println("Connected to socket");
//
//        PandaMessages.BurpMessage msg = PandaMessages.BurpMessage.newBuilder().setCommand(
//                PandaMessages.Command.newBuilder().setCmd("begin_record").build()
//        ).build();
//
//        try {
//            sendMessage(msg, pySock);
//        } catch (IOException e) {
//            e.printStackTrace();
//            return;
//        }
//        stdout.println("Sent start msg");
//
//        try {
//            Thread.sleep(10000);
//        } catch (InterruptedException e) {
//            e.printStackTrace();
//        }
//
//        PandaMessages.BurpMessage msg2 = PandaMessages.BurpMessage.newBuilder().setCommand(
//                PandaMessages.Command.newBuilder().setCmd("end_record").build()
//        ).build();
//
//        try {
//            sendMessage(msg2, pySock);
//        } catch (IOException e) {
//            e.printStackTrace();
//            return;
//        }
//        stdout.println("Sent stop msg");

    }

    public void sendMessage(Message msg, Socket sock) throws IOException {
        byte[] msgBytes = msg.toByteArray();

        ByteBuffer sendBuf = ByteBuffer.allocate(msgBytes.length + 4);
        sendBuf.putInt(msgBytes.length + 4);  // defaults to big-endian
        sendBuf.put(msgBytes);
        sendBuf.flip();

        OutputStream oStream = sock.getOutputStream();
        BufferedOutputStream bOStream = new BufferedOutputStream(oStream);
        bOStream.write(sendBuf.array());
        bOStream.flush();
    }

}
