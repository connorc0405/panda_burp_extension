package com.ccumming.burp.model;

import com.ccumming.burp.PandaMessages;

/**
 * Interface for a model of our data.
 */
public interface IModel {

  /**
   * Validate the given hostname.
   *
   * @param host the hostname.
   * @return true if the hostname is valid, false otherwise.
   */
  boolean isValidHostname(String host);

  /**
   * Validate the given port.
   *
   * @param port the port number.
   * @return true if the port is valid, false otherwise.
   */
  boolean isValidPort(String port);

  /**
   * Validate the user's taint selection string.
   *
   * @param taintSelection the taint selection string.
   * @return true if the selection is valid, false otherwise.
   */
  boolean validateTaintSelection(String taintSelection);


  PandaMessages.TaintResult runRRAndTaint(String pandaServerHost, int pandaServerPort,
                                          String httpServerHost, int httpServerPort,
                                          byte[] httpMsg, String taintSelection) throws Exception;

}
