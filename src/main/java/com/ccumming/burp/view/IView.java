package com.ccumming.burp.view;

import java.awt.event.ActionListener;

import burp.ITab;

public interface IView extends ITab {

  /**
   * Return the HTTP message.
   * @return the HTTP message byte array.
   */
  public byte[] getHttpMessage();

  /**
   * Return the taint selection.
   * @return a taint selection {@link String}.
   */
  public String getTaintSelection();

  /**
   * Display PANDA taint results on the screen.
   * @param results the taint results.
   */
  public void displayTaintResults(String results);

  /**
   * Register a listener for view buttons.
   * @param listener the listener to handle button presses.
   */
  public void registerButtonListener(ActionListener listener);

  /**
   * Return the HTTP Server Host field.
   * @return the HTTP server host.
   */
  public String getHttpServerHost();

  /**
   * Return the HTTP Server port field.
   * @return the HTTP server port.
   */
  public String getHttpServerPort();

  /**
   * Return the PANDA Server Host field.
   * @return the PANDA server host.
   */
  public String getPandaServerHost();

  /**
   * Return the PANDA Server port field.
   * @return the PANDA server port.
   */
  public String getPandaServerPort();

}
