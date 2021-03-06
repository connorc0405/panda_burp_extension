package com.ccumming.burp.controller;

import com.ccumming.burp.PandaMessages;
import com.ccumming.burp.model.IModel;
import com.ccumming.burp.view.IView;

import java.awt.event.ActionEvent;
import java.io.PrintWriter;
import java.util.concurrent.ExecutionException;

import javax.swing.JButton;

import javax.swing.SwingWorker;

import burp.IBurpExtenderCallbacks;

public class Controller implements IController {

  private final IModel model;
  private final IView view;
  private final PrintWriter stdout;
  private final PrintWriter stderr;

  public Controller(IModel model, IView view, IBurpExtenderCallbacks callbacks) {
    this.model = model;
    this.view = view;
    this.stdout = new PrintWriter(callbacks.getStdout(), true);
    this.stderr = new PrintWriter(callbacks.getStderr(), true);
  }

  @Override
  public void actionPerformed(ActionEvent e) {
    JButton buttonPressed = (JButton)e.getSource();
    if ("Send".equals(buttonPressed.getText())) {
      if (!validateSendInput()) {  // Do this in model?
        return;
      }
      SwingWorker<PandaMessages.TaintResult, Void> worker = new SwingWorker<>() {
        @Override
        protected PandaMessages.TaintResult doInBackground() throws Exception {
          return model.runRRAndTaint(view.getPandaServerHost(),
                  Integer.parseInt(view.getPandaServerPort()), view.getHttpServerHost(),
                  Integer.parseInt(view.getHttpServerPort()), view.getHttpMessage(),
                  view.getTaintSelection());
        }

        @Override
        protected void done() {
          try {
            PandaMessages.TaintResult result = get();
            view.displayTaintResults(result.toString());  // TODO update when format is decided
          } catch (InterruptedException iEx) {
            // TODO cancelled run?
          } catch (ExecutionException eEx) {
            // Catches any exceptions that occurred during doInBackground
            Throwable cause = eEx.getCause();
            String errorMessage;
            if (cause == null) {
              errorMessage = "Unknown error";
            } else {
              errorMessage = cause.getMessage();
              cause.printStackTrace(stderr);
            }

            view.alertUser(errorMessage);
          }
        }
      };
      worker.execute();
    } else {
      this.stderr.println("Idk that button");
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
      view.alertUser("Valid HTTP server address and port are required");
      return false;
    }

    // Check PANDA server address and port
    if (!model.isValidHostname(view.getPandaServerHost()) || !model.isValidPort(view.getPandaServerPort())) {
      view.alertUser("Valid PANDA server address and port are required");
      return false;
    }

    // Check HTTP not null (empty)
    byte[] httpMsg = view.getHttpMessage();
    if (httpMsg == null) {
      view.alertUser("HTTP message cannot be empty");
      return false;
    }

    // Validate taint selection formatting
    String taintSelection = view.getTaintSelection();
    if (!model.validateTaintSelection(taintSelection)) {
      view.alertUser("Taint selection is empty or invalid");
      return false;
    }

    return true;
  }

}
