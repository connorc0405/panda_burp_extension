package com.ccumming.burp.model;

import com.ccumming.burp.PandaMessages;
import com.ccumming.burp.util.NetUtils;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.Socket;

import burp.IBurpExtenderCallbacks;

/**
 * This is just a container for our validation methods right now.
 */
public class Model implements IModel {

  private final IBurpExtenderCallbacks callbacks;
  private Socket pySock;

  public Model(IBurpExtenderCallbacks callbacks) {
    this.callbacks = callbacks;
  }


  @Override
  public boolean isValidHostname(String host) {
    return true;  // TODO
  }

  @Override
  public boolean isValidPort(String port) {
    int intPort;
    try {
      intPort = Integer.parseInt(port);
    } catch (NumberFormatException e) {
      return false;
    }

    return intPort > 0 && intPort <= 65535;
  }

  /**
   * Validate the tainted bytes formatting selected by the user.
   * Format: <index1>,<index2>:<index3>,... where ":" represents a range of bytes (inclusive).
   * Order does not matter.
   *
   * @param taintSelection the taint selection {@link String}.
   * @return whether the taint selection is of valid format.
   */
  @Override
  public boolean validateTaintSelection(String taintSelection) {

    if (taintSelection.equals("")) {
      return false;
    }

    boolean expectingNewGroup = true;
    boolean rhsRange = false;
    for (int i = 0; i < taintSelection.length()-1; i++) {
      char curChar = taintSelection.charAt(i);
      if (curChar == ',') {
        if (expectingNewGroup) {
          return false;
        } else {
          expectingNewGroup = true;
        }
        if (rhsRange) {
          if (taintSelection.charAt(i - 1) == ':') {
            return false;
          }
          rhsRange = false;
        }
      } else if (curChar == ':') {
        if (expectingNewGroup) {
          return false;
        }
        if (rhsRange) {
          return false;
        } else {
          rhsRange = true;
        }
      } else if (Character.isDigit(curChar)) {
        if (expectingNewGroup) {
          expectingNewGroup = false;
        }
      } else {
        return false;
      }
    }
    return Character.isDigit(taintSelection.charAt(taintSelection.length() - 1));
  }

  @Override
  public PandaMessages.TaintResult runRRAndTaint(String pandaServerHost, int pandaServerPort,
                                                 String httpServerHost, int httpServerPort,
                                                 byte[] httpMsg, String taintSelection) throws Exception {
      // TODO Run ops in EDT thread?

      // Open socket
      connectPandaServer(pandaServerHost, pandaServerPort);

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
    new PrintWriter(callbacks.getStdout(), true).println("sent start");


    // Receive confirmation of recording start
      PandaMessages.BurpMessage resp = NetUtils.recvMessage(this.pySock);
      if (!resp.hasResponse()) {
        throw new Exception("BurpMessage should include a Response");
      }
      if (resp.getResponse().getRespType() != PandaMessages.ResponseType.RecordingStarted) {
        throw new Exception("Expected response type to be RecordingStarted");
      }
      new PrintWriter(callbacks.getStdout(), true).println("Got start confirmation");
      // Send HTTP and receive response
      callbacks.makeHttpRequest(httpServerHost, httpServerPort, false, httpMsg);
    new PrintWriter(callbacks.getStdout(), true).println("sent http");
      // Send stop recording command
      NetUtils.sendMessage(
              PandaMessages.BurpMessage.newBuilder()
                      .setCommand(
                              PandaMessages.Command.newBuilder()
                                      .setCmdType(PandaMessages.CommandType.StopRecording)
                                      .build()
                      )
                      .build()
              , this.pySock);
    new PrintWriter(callbacks.getStdout(), true).println("sent stop");

      // Receive confirmation of recording stopped
      resp = NetUtils.recvMessage(this.pySock);
      if (!resp.hasResponse()) {
        throw new Exception("BurpMessage should include a Response");
      }
      if (resp.getResponse().getRespType() != PandaMessages.ResponseType.RecordingStopped) {
        throw new Exception("Expected response type to be RecordingStopped");
      }
    new PrintWriter(callbacks.getStdout(), true).println("got stop");

      // Send taint bytes
      NetUtils.sendMessage(
              PandaMessages.BurpMessage.newBuilder()
                      .setCommand(
                              PandaMessages.Command.newBuilder()
                                      .setCmdType(PandaMessages.CommandType.SetTaintBytes)
                                      .setTaintBytes(taintSelection)
                                      .build()
                      )
                      .build()
              , this.pySock);
    new PrintWriter(callbacks.getStdout(), true).println("sent taint");

    // Receive taint result
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
    new PrintWriter(callbacks.getStdout(), true).println("got ret");

    return resp.getResponse().getTaintResult();
    }

  /**
   * Open a connection to the PANDA server.
   * Sets the socket timeout to 10 seconds.
   * Requirements: The PANDA server address and port fields
   * must not be empty/invalid.
   *
   * @throws IOException on error.
   */
  private void connectPandaServer(String pandaServerHost, int pandaServerPort) throws IOException {
    this.pySock = new Socket(pandaServerHost, pandaServerPort);
    this.pySock.setSoTimeout(10*3000);
  }
}
