package com.ccumming.burp.model;

/**
 * Interface for a model of our data.
 */
public interface IModel {

  boolean isValidHostname(String host);

  boolean isValidPort(String port);

  boolean validateTaintSelection(String taintSelection);

}
