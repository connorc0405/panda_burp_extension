package com.ccumming.burp.view;

import com.ccumming.burp.HostControlPanel;

import java.awt.Color;
import java.awt.Component;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionListener;

import javax.swing.JPanel;
import javax.swing.JSplitPane;
import javax.swing.JTextArea;

import burp.IBurpExtenderCallbacks;
import burp.IMessageEditor;
import burp.ITab;
import burp.ITextEditor;


public class PandaTabView extends JPanel implements ITab, IView {

  private final HostControlPanel hostControlPanel;
  private final JTextArea taintResults;

  public PandaTabView(IBurpExtenderCallbacks callbacks) {
    hostControlPanel = new HostControlPanel();
    hostControlPanel.setBackground(Color.LIGHT_GRAY);

    this.setLayout(new GridBagLayout());
    GridBagConstraints c = new GridBagConstraints();

    c.fill = GridBagConstraints.HORIZONTAL;
    c.anchor = GridBagConstraints.NORTHWEST;
    c.gridx = 0;
    c.gridy = 0;
    c.weighty = 0.0;
    c.weightx = 1.0;
    this.add(hostControlPanel, c);

    IMessageEditor requestEditor = callbacks.createMessageEditor(null, true);

    ITextEditor taintGroupEditor = callbacks.createTextEditor();

    JSplitPane editorSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, requestEditor.getComponent(), taintGroupEditor.getComponent());

    this.taintResults = new JTextArea();
    taintResults.setText("Taint Results Placeholder!!!!");
    taintResults.setEditable(false);
    JSplitPane editorResultsSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, editorSplit, taintResults);

    c.fill = GridBagConstraints.BOTH;
    c.anchor = GridBagConstraints.EAST;
    c.gridx = 0;
    c.gridy = GridBagConstraints.RELATIVE;
    c.weighty = 1.0;
    c.weightx = 1.0;
    this.add(editorResultsSplit, c);

  }

  @Override
  public String getTabCaption() {
    return "PANDA";
  }

  @Override
  public Component getUiComponent() {
    return this;
  }

  @Override
  public void displayTaintResults(String results) {
    this.taintResults.setText(results);
  }

  @Override
  public void registerButtonListener(ActionListener listener) {
    this.hostControlPanel.registerButtonListener(listener);
  }

}
