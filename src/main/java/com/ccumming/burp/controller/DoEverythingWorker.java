package com.ccumming.burp.controller;

import com.ccumming.burp.PandaMessages;

import java.io.IOException;
import java.io.PrintWriter;

import javax.swing.SwingWorker;

public class DoEverythingWorker extends SwingWorker<Void, Void> {

  PrintWriter stdout;
  PrintWriter stderr;

  DoEverythingWorker(PrintWriter stdout, PrintWriter stderr) {
    super();
    this.stdout = stdout;
    this.stderr = stderr;
  }

  @Override
  protected Void doInBackground() throws Exception {
    throw new Exception();

//    // Start recording
//    this.sendMessage(
//            PandaMessages.BurpMessage.newBuilder()
//                    .setCommand(
//                            PandaMessages.Command.newBuilder()
//                                    .setCmdType(PandaMessages.CommandType.StartRecording)
//                                    .build()
//                    )
//                    .build()
//            , this.pySock);
//
//    PandaMessages.BurpMessage resp = this.recvMessage(this.pySock);
//    stdout.println(resp);

    //return null;
  }
}
