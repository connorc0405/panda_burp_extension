package com.ccumming.burp.controller;

import com.ccumming.burp.PandaMessages;
import com.ccumming.burp.model.IModel;
import com.ccumming.burp.view.IView;

import java.awt.event.ActionEvent;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.ByteBuffer;

import javax.swing.JButton;

import burp.IBurpExtenderCallbacks;

public class Controller implements IController {

  private final IModel model;
  private final IView view;
  private final ProgStatus progStatus;
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
        this.stdout.println("Send was pressed");
        break;
      case "Connect":
        this.stdout.println("Connect was pressed");
        break;
      default:
        this.stderr.println("Idk that button");
        break;
    }
    stdout.println(((JButton)e.getSource()).getText() + " was pressed.");
  }

  @Override
  public void sendMessage(PandaMessages.BurpMessage message, Socket sock) throws IOException {
    byte[] msgBytes = message.toByteArray();

    ByteBuffer sendBuf = ByteBuffer.allocate(msgBytes.length + 4);
    sendBuf.putInt(msgBytes.length);  // defaults to big-endian TODO feel like the size is wrong.
    sendBuf.put(msgBytes);
    sendBuf.flip();

    OutputStream oStream = sock.getOutputStream();
    BufferedOutputStream bOStream = new BufferedOutputStream(oStream);
    bOStream.write(sendBuf.array());
    bOStream.flush();  // TODO is this blocking or not?
  }

  @Override
  public PandaMessages.BurpMessage recvMessage(Socket sock) throws IOException {
    byte[] len_buf = new byte[4];

    int bytes_read = 0;
    while (bytes_read < len_buf.length) {
      bytes_read += sock.getInputStream().read(len_buf, bytes_read, len_buf.length - bytes_read);
    }

    int payload_size = ByteBuffer.wrap(len_buf).getInt();

    byte[] payload_buf = new byte[payload_size];

    bytes_read = 0;
    while (bytes_read < payload_buf.length) {
      bytes_read += sock.getInputStream().read(payload_buf, bytes_read, payload_buf.length - bytes_read);
    }

    PandaMessages.BurpMessage msg = PandaMessages.BurpMessage.parseFrom(payload_buf);
    return msg;
  }

}
