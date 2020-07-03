package com.ccumming.burp.controller;

import java.awt.event.ActionEvent;
import java.io.PrintWriter;

import javax.swing.JButton;

import burp.IBurpExtenderCallbacks;

public class Controller implements IController {

  private final PrintWriter stdout;
  private final PrintWriter stderr;

  public Controller(IBurpExtenderCallbacks callbacks) {
    this.stdout = new PrintWriter(callbacks.getStdout(), true);
    this.stderr = new PrintWriter(callbacks.getStderr(), true);
  }

  @Override
  public void actionPerformed(ActionEvent e) {
    stdout.println(((JButton)e.getSource()).getText() + " was pressed.");
  }


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
