package com.ccumming.burp.controller;

import com.google.protobuf.Message;

import com.ccumming.burp.PandaMessages;

import java.awt.event.ActionListener;
import java.io.IOException;
import java.net.Socket;

public interface IController extends ActionListener {

  /**
   * Send a {@link Message} over the provided {@link Socket}.
   * @param message the message to send.
   * @param sock the socket to use.
   */
  public void sendMessage(PandaMessages.BurpMessage message, Socket sock) throws IOException;

  /**
   * Return a {@link Message} from the provided {@link Socket}.
   * @param sock the socket to read from.
   * @return the received {@link Message}.
   */
  public PandaMessages.BurpMessage recvMessage(Socket sock) throws IOException;

}
