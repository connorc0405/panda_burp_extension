package com.ccumming.burp.view;

import java.awt.event.ActionListener;

import javax.swing.GroupLayout;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;

public class HostControlPanel extends JPanel {

  private final JLabel httpServerHostLabel;
  private final JTextField httpServerHostField;
  private final JLabel httpServerPortLabel;
  private final JTextField httpServerPortField;
  private final JButton httpServerSendButton;

  private final JLabel pandaServerHostLabel;
  private final JTextField pandaServerHostField;
  private final JLabel pandaServerPortLabel;
  private final JTextField pandaServerPortField;

  public HostControlPanel() {
    this.httpServerHostLabel = new JLabel("HTTP Server Host");
    this.httpServerHostField = new JTextField("", 20);
    this.httpServerPortLabel = new JLabel(":");
    this.httpServerPortField = new JTextField("", 5);
    this.httpServerSendButton = new JButton("Send");

    this.pandaServerHostLabel = new JLabel("PANDA Server Host");
    this.pandaServerHostField = new JTextField("", 20);
    this.pandaServerPortLabel = new JLabel(":");
    this.pandaServerPortField = new JTextField("", 5);


    GroupLayout layout = new GroupLayout(this);
    this.setLayout(layout);

    layout.setAutoCreateGaps(true);
    layout.setAutoCreateContainerGaps(true);

    layout.setHorizontalGroup(layout.createSequentialGroup()
            .addGroup(layout.createParallelGroup()
                    .addComponent(httpServerHostLabel)
                    .addComponent(pandaServerHostLabel))
            .addGroup(layout.createParallelGroup()
                    .addComponent(httpServerHostField)
                    .addComponent(pandaServerHostField))
            .addGroup(layout.createParallelGroup()
                    .addComponent(httpServerPortLabel)
                    .addComponent(pandaServerPortLabel))
            .addGroup(layout.createParallelGroup()
                    .addComponent(httpServerPortField)
                    .addComponent(pandaServerPortField))
            .addGroup(layout.createParallelGroup()
                    .addComponent(httpServerSendButton)));

    layout.setVerticalGroup(layout.createSequentialGroup()
            .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(httpServerHostLabel)
                    .addComponent(httpServerHostField)
                    .addComponent(httpServerPortLabel)
                    .addComponent(httpServerPortField)
                    .addComponent(httpServerSendButton))
            .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(pandaServerHostLabel)
                    .addComponent(pandaServerHostField)
                    .addComponent(pandaServerPortLabel)
                    .addComponent(pandaServerPortField)));
  }

  public void registerButtonListener(ActionListener listener) {
    this.httpServerSendButton.addActionListener(listener);
  }

  public String getHttpServerHost() {
    return this.httpServerHostField.getText();
  }

  public String getHttpServerPort() {
    return this.httpServerPortField.getText();
  }

  public String getPandaServerHost() {
    return this.pandaServerHostField.getText();
  }

  public String getPandaServerPort() {
    return this.pandaServerPortField.getText();
  }

}
