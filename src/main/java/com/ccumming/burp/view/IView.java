package com.ccumming.burp.view;

import java.awt.event.ActionListener;

import burp.ITab;

/**
 * Interface for a view.
 */
public interface IView extends ITab {

  /**
   * Return the HTTP message.
   * @return the HTTP message byte array.
   */
  byte[] getHttpMessage();

  /**
   * Return the taint selection.
   * @return a taint selection {@link String}.
   */
  String getTaintSelection();

  /**
   * Display PANDA taint results on the screen.
   * @param results the taint results.
   */
  void displayTaintResults(String results);

  /**
   * Register a listener for view buttons.
   * @param listener the listener to handle button presses.
   */
  void registerButtonListener(ActionListener listener);

  /**
   * Return the HTTP Server Host field.
   * @return the HTTP server host.
   */
  String getHttpServerHost();

  /**
   * Return the HTTP Server port field.
   * @return the HTTP server port.
   */
  String getHttpServerPort();

  /**
   * Return the PANDA Server Host field.
   * @return the PANDA server host.
   */
  String getPandaServerHost();

  /**
   * Return the PANDA Server port field.
   * @return the PANDA server port.
   */
  String getPandaServerPort();

}
