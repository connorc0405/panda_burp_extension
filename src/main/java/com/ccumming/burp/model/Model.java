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
    if (!Character.isDigit(taintSelection.charAt(taintSelection.length()-1))) {
      return false;
    }
    return true;
  }
}
