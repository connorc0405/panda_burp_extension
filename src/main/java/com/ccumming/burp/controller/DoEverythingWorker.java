package com.ccumming.burp.controller;

import com.ccumming.burp.PandaMessages;
import com.ccumming.burp.model.IModel;
import com.ccumming.burp.util.NetUtils;
import com.ccumming.burp.view.IView;

import java.io.PrintWriter;
import java.net.Socket;
import java.util.concurrent.ExecutionException;

import javax.swing.SwingWorker;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IHttpService;

/**
 * This will run as a new thread and will handle everything from sending the command to start recording, to receiving the final result.
 */
public class DoEverythingWorker extends SwingWorker<PandaMessages.TaintResult, Void> {

  private final IModel model;
  private final IView view;
  Socket pySock;
  IBurpExtenderCallbacks callbacks;
  PrintWriter stdout;
  PrintWriter stderr;

  DoEverythingWorker(IModel model, IView view, Socket pySock, IBurpExtenderCallbacks callbacks, PrintWriter stdout, PrintWriter stderr) {
    super();
    this.model = model;
    this.view = view;
    this.pySock = pySock;
    this.callbacks = callbacks;
    this.stdout = stdout;
    this.stderr = stderr;
  }

  @Override
  protected PandaMessages.TaintResult doInBackground() throws Exception {

    // TODO better handling of errors (don't throw exceptions everywhere)?

    // Validate taint selection formatting
    if (!model.validateTaintSelection(view.getTaintSelection())) {
      throw new Exception("Taint selection is incorrectly formatted");  // TODO more specific exception?
    }

    // Check HTTP not null (empty)
    byte[] httpMsg = view.getHttpMessage();
    if (httpMsg == null) {
      throw new Exception("HTTP message cannot be empty");
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
    IHttpRequestResponse response = callbacks.makeHttpRequest(httpService, httpMsg);

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
}
