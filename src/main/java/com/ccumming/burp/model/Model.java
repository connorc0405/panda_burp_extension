package com.ccumming.burp.model;

/**
 * This is just a container for our validation methods right now.
 */
public class Model implements IModel {

  @Override
  public boolean validateHost(String host) {
    return true;  // TODO
  }

  @Override
  public boolean validatePort(int port) {
    return port > 0 && port <= 65535;
  }

  @Override
  public boolean validateTaintSelection(String taintSelection) {
    return true; // TODO
  }

}
