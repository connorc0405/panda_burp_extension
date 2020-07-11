package com.ccumming.burp.controller;

import com.ccumming.burp.PandaMessages;
import com.ccumming.burp.model.IModel;
import com.ccumming.burp.view.IView;

import java.awt.event.ActionEvent;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.Socket;

import javax.swing.JButton;
import javax.swing.SwingWorker;

import burp.IBurpExtenderCallbacks;

public class Controller implements IController {

  private final IModel model;
  private final IView view;
  private Socket pySock;
  private ProgStatus progStatus;
  private final PrintWriter stdout;
  private final PrintWriter stderr;

  public Controller(IModel model, IView view, IBurpExtenderCallbacks callbacks) {
    this.model = model;
    this.view = view;
    this.progStatus = ProgStatus.NOT_CONNECTED;
    this.stdout = new PrintWriter(callbacks.getStdout(), true);
    this.stderr = new PrintWriter(callbacks.getStderr(), true);
  }

  @Override
  public void actionPerformed(ActionEvent e) {
    JButton buttonPressed = (JButton)e.getSource();
    switch (buttonPressed.getText()) {
      case "Send":
        SwingWorker<PandaMessages.TaintResult, Void> worker = new DoEverythingWorker(this.pySock, this.stdout, this.stderr);
        worker.execute();
        break;
      case "Connect":
        this.connectPandaServer();
        break;
      default:
        this.stderr.println("Idk that button");
        break;
    }
    stdout.println(((JButton)e.getSource()).getText() + " was pressed.");
  }

  private void connectPandaServer() {
    String pandaHost = this.view.getPandaServerHost();
    int pandaPort = Integer.parseInt(this.view.getPandaServerPort());
    try {
      this.pySock = new Socket(pandaHost, pandaPort);
      this.progStatus = ProgStatus.CONNECTED;
    } catch (IOException ex) {
      ex.printStackTrace(stderr);
    }
  }

}
