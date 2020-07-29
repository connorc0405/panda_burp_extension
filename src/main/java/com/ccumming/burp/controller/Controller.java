package com.ccumming.burp.controller;

import com.ccumming.burp.PandaMessages;
import com.ccumming.burp.model.IModel;
import com.ccumming.burp.view.AbstractView;

import java.awt.event.ActionEvent;
import java.io.PrintWriter;

import javax.swing.JButton;
import javax.swing.JOptionPane;
import javax.swing.SwingWorker;

import burp.IBurpExtenderCallbacks;

public class Controller implements IController {

  private final IModel model;
  private final AbstractView view;
  private final IBurpExtenderCallbacks callbacks;
  private final PrintWriter stdout;
  private final PrintWriter stderr;

  public Controller(IModel model, AbstractView view, IBurpExtenderCallbacks callbacks) {
    this.model = model;
    this.view = view;
    this.callbacks = callbacks;
    this.stdout = new PrintWriter(callbacks.getStdout(), true);
    this.stderr = new PrintWriter(callbacks.getStderr(), true);
  }

  @Override
  public void actionPerformed(ActionEvent e) {
    JButton buttonPressed = (JButton)e.getSource();
    switch (buttonPressed.getText()) {
      case "Send":
        if (!validateSendInput()) {
          return;
        }
        SwingWorker<PandaMessages.TaintResult, Void> worker = new DoEverythingWorker(this.view, this.callbacks, this.stdout, this.stderr);
        worker.execute();
        break;
      default:
        this.stderr.println("Idk that button");
        break;
    }
    stdout.println(((JButton)e.getSource()).getText() + " was pressed.");
  }

  /**
   * Determine if we can start the process of communicating with PANDA.
   * Checks relevant fields.  Does not check the socket.
   * Displays alert box if field is not supplied/valid.
   * @return if the required fields are valid.
   */
  private boolean validateSendInput() {
    String dialogTitle = "Insufficient information";

    // Check HTTP server address and port
    if (!model.isValidHostname(view.getHttpServerHost()) || !model.isValidPort(view.getHttpServerPort())) {
      JOptionPane.showMessageDialog(this.view,
              "Valid HTTP server address and port are required",
              dialogTitle,
              JOptionPane.WARNING_MESSAGE);
      return false;
    }

    // Check PANDA server address and port
    if (!model.isValidHostname(view.getPandaServerHost()) || !model.isValidPort(view.getPandaServerPort())) {
      JOptionPane.showMessageDialog(this.view,
              "Valid PANDA server address and port are required",
              dialogTitle,
              JOptionPane.WARNING_MESSAGE);
      return false;
    }

    // Check HTTP not null (empty)
    byte[] httpMsg = view.getHttpMessage();
    if (httpMsg == null) {
      JOptionPane.showMessageDialog(this.view,
              "HTTP message cannot be empty",
              dialogTitle,
              JOptionPane.WARNING_MESSAGE);
      return false;
    }

    // Validate taint selection formatting
    String taintSelection = view.getTaintSelection();
    if (!model.validateTaintSelection(taintSelection)) {
      JOptionPane.showMessageDialog(this.view,
              "Taint selection is empty or invalid",
              dialogTitle,
              JOptionPane.WARNING_MESSAGE);
      return false;
    }

    return true;
  }

}
