package com.ccumming.burp.controller;

import com.ccumming.burp.model.IModel;
import com.ccumming.burp.view.IView;

import java.awt.event.ActionEvent;
import java.io.PrintWriter;

import javax.swing.JButton;

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
    switch (buttonPressed.getText()) {
      case "Send":
        this.stdout.println("Send was pressed");
        break;
      case "Connect":
        this.stdout.println("Connect was pressed");
        break;
      default:
        stderr.println("Idk that button");
        break;
    }
    stdout.println(((JButton)e.getSource()).getText() + " was pressed.");
  }



}
