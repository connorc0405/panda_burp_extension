package com.ccumming.burp.model;

/**
 * Interface for a model of our data.
 */
public interface IModel {

  boolean validateHost(String host);

  boolean validatePort(int port);

  boolean validateTaintSelection(String taintSelection);

}
