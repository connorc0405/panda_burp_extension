package com.ccumming.burp.controller;

import com.ccumming.burp.PandaMessages;
import com.ccumming.burp.model.IModel;
import com.ccumming.burp.util.NetUtils;
import com.ccumming.burp.view.AbstractView;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutionException;

import javax.swing.JOptionPane;
import javax.swing.SwingWorker;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IHttpService;

/**
 * This will run as a new thread and will handle everything from sending the command to start recording, to receiving the final result.
 */
public class DoEverythingWorker extends SwingWorker<PandaMessages.TaintResult, Void> {

  private final AbstractView view;
  Socket pySock;
  IBurpExtenderCallbacks callbacks;
  PrintWriter stdout;
  PrintWriter stderr;

  DoEverythingWorker(AbstractView view, IBurpExtenderCallbacks callbacks, PrintWriter stdout, PrintWriter stderr) {
    super();
    this.view = view;
    this.callbacks = callbacks;
    this.stdout = stdout;
    this.stderr = stderr;
  }

  /**
   * Return the results of a PANDA taint run on the selected bytes of user-provided HTTP.
   * Requirements:
   *  The HTTP field must not be empty.
   *  The taint selection field must not be empty.
   *  The HTTP and PANDA server addresses and ports must not be empty.
   * @return a {@link com.ccumming.burp.PandaMessages.TaintResult}.
   * @throws Exception if one occurs
   */
  @Override
  protected PandaMessages.TaintResult doInBackground() throws Exception {
    // TODO Run ops in EDT thread?

    // Open socket
    if (!connectPandaServer()) {
      return null;
    }

    // Send start recording command
    NetUtils.sendMessage(
            PandaMessages.BurpMessage.newBuilder()
                    .setCommand(
                            PandaMessages.Command.newBuilder()
                                    .setCmdType(PandaMessages.CommandType.StartRecording)
                                    .build()
                    )
                    .build()
            , this.pySock);

    // Receive confirmation of recording start
    PandaMessages.BurpMessage resp = NetUtils.recvMessage(this.pySock);
    if (!resp.hasResponse()) {
      throw new Exception("BurpMessage should include a Response");
    }
    if (resp.getResponse().getRespType() != PandaMessages.ResponseType.RecordingStarted) {
      throw new Exception("Expected response type to be RecordingStarted");
    }

    // TODO Send HTTP and receive response
    IHttpService httpService = new IHttpService() {
      @Override
      public String getHost() {
        return view.getHttpServerHost();
      }

      @Override
      public int getPort() {
        return Integer.parseInt(view.getHttpServerPort());
        // TODO change return type to int
      }

      @Override
      public String getProtocol() {
        return "http";
      }
    };
    IHttpRequestResponse response = callbacks.makeHttpRequest(httpService, view.getHttpMessage());

    // TODO Send stop recording command
    NetUtils.sendMessage(
            PandaMessages.BurpMessage.newBuilder()
                    .setCommand(
                            PandaMessages.Command.newBuilder()
                                    .setCmdType(PandaMessages.CommandType.StopRecording)
                                    .build()
                    )
                    .build()
            , this.pySock);

    // TODO Receive confirmation of recording stopped
    resp = NetUtils.recvMessage(this.pySock);
    if (!resp.hasResponse()) {
      throw new Exception("BurpMessage should include a Response");
    }
    if (resp.getResponse().getRespType() != PandaMessages.ResponseType.RecordingStopped) {
      throw new Exception("Expected response type to be RecordingStopped");
    }

    // TODO Send taint bytes
    NetUtils.sendMessage(
            PandaMessages.BurpMessage.newBuilder()
                    .setCommand(
                            PandaMessages.Command.newBuilder()
                                    .setCmdType(PandaMessages.CommandType.SetTaintBytes)
                                    .setTaintBytes(view.getTaintSelection())
                                    .build()
                    )
                    .build()
            , this.pySock);

    // TODO Receive taint result
    resp = NetUtils.recvMessage(this.pySock);
    if (!resp.hasResponse()) {
      throw new Exception("BurpMessage should include a Response");
    }
    if (resp.getResponse().getRespType() != PandaMessages.ResponseType.ReturnTaintResult) {
      throw new Exception("Expected response type to be ReturnTaintResult");
    }
    if (!resp.getResponse().hasTaintResult()) {
      throw new Exception("Expected response to include TaintResult");
    }

    return resp.getResponse().getTaintResult();
  }

  @Override
  protected void done() {
    try {
      get();
    } catch (InterruptedException | ExecutionException ex) {
      ex.printStackTrace(this.stderr);
    }
  }

  /**
   * Open a connection to the PANDA server.
   * Requirements:
   *  The PANDA server address and port fields must not be empty/invalid.
   *
   * @return true on success, false on failure.
   */
  private boolean connectPandaServer() {
    String pandaHost = this.view.getPandaServerHost();
    int pandaPort = Integer.parseInt(this.view.getPandaServerPort());
    try {
      this.pySock = new Socket(pandaHost, pandaPort);
    } catch (IOException ex) {
      JOptionPane.showMessageDialog(this.view,
              "Could not connect to PANDA server",
              "Connection Error",
              JOptionPane.WARNING_MESSAGE);
      return false;
    }
    return true;
  }
}
