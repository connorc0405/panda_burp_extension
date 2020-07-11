package com.ccumming.burp.controller;

import com.ccumming.burp.PandaMessages;
import com.ccumming.burp.model.IModel;
import com.ccumming.burp.util.NetUtils;

import java.io.PrintWriter;
import java.net.Socket;
import java.util.concurrent.ExecutionException;

import javax.swing.SwingWorker;

/**
 * This will run as a new thread and will handle everything from sending the command to start recording, to receiving the final result.
 */
public class DoEverythingWorker extends SwingWorker<PandaMessages.TaintResult, Void> {

  Socket pySock;
  PrintWriter stdout;
  PrintWriter stderr;

  DoEverythingWorker(Socket pySock, PrintWriter stdout, PrintWriter stderr) {
    super();
    this.pySock = pySock;
    this.stdout = stdout;
    this.stderr = stderr;
  }

  @Override
  protected PandaMessages.TaintResult doInBackground() throws Exception {

    // TODO Validate taint preference formatting

    stdout.println("About to send 1st msg");

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

    // TODO Send HTTP


    // TODO Receive HTTP response

    // TODO Send stop recording command

    // TODO Receive confirmation of recording stopped

    // TODO Send taint bytes

    // TODO Receive taint result

    return null;
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
