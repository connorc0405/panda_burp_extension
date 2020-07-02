package burp;


import java.awt.Color;
import java.awt.Component;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;

import javax.swing.JPanel;
import javax.swing.JSplitPane;
import javax.swing.JTextArea;


public class PandaTabView extends JPanel implements ITab {

  private final JPanel hostControlPanel;

  PandaTabView(IBurpExtenderCallbacks callbacks) {
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

    JTextArea taintResults = new JTextArea();
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
}