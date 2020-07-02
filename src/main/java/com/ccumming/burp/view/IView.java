package com.ccumming.burp.view;

import java.awt.event.ActionListener;

public interface IView {

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

}
