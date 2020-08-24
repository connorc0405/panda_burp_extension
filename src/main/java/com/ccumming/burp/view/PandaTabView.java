package com.ccumming.burp.view;

import java.awt.Color;
import java.awt.Component;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.PrintWriter;
import java.lang.reflect.InvocationTargetException;

import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JSplitPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultHighlighter;
import javax.swing.text.Highlighter;

import burp.IBurpExtenderCallbacks;
import burp.ITab;


public class PandaTabView extends JPanel implements ITab, IView {

  private final HostControlPanel hostControlPanel;
  private final JTextArea taintResults;
  private final JTextArea requestEditor;

  private final PrintWriter stderr;

  public PandaTabView(IBurpExtenderCallbacks callbacks) {
    this.stderr = new PrintWriter(callbacks.getStderr(), true);
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

    // Request editor
    this.requestEditor = new JTextArea();
    requestEditor.setText("GET / HTTP/1.1\r\n");
    Highlighter highlighter = new DefaultHighlighter();
    requestEditor.setHighlighter(highlighter);
    Highlighter.HighlightPainter painter = new DefaultHighlighter.DefaultHighlightPainter(Color.YELLOW);
    requestEditor.addMouseListener(new MouseAdapter() {
      @Override
      public void mousePressed(MouseEvent e) {
        if (e.isPopupTrigger()) {
          doPopUp(e);
        }
      }
      @Override
      public void mouseReleased(MouseEvent e) {
        if (e.isPopupTrigger()) {
          doPopUp(e);
        }
      }

      private void doPopUp(MouseEvent ev) {
        JPopupMenu menu = new JPopupMenu();

        JMenuItem addTaintMenuItem = new JMenuItem("Taint selection");
        if (addTaintMenuItem.getActionListeners().length == 0) {
          addTaintMenuItem.addActionListener(e -> {
            int selectionStart = requestEditor.getSelectionStart();
            int selectionEnd = requestEditor.getSelectionEnd();
            if (selectionStart != selectionEnd) {
              try {
                highlighter.addHighlight(selectionStart, selectionEnd, painter);
              } catch (BadLocationException badLocationException) {
                badLocationException.printStackTrace(stderr);
              }

            }
          });
        }
        menu.add(addTaintMenuItem);

        JMenuItem removeTaintMenuItem = new JMenuItem("Remove all taint selections");
        if (removeTaintMenuItem.getActionListeners().length == 0) {
          removeTaintMenuItem.addActionListener(e -> {
            highlighter.removeAllHighlights();
          });
        }
        menu.add(removeTaintMenuItem);

        menu.show(requestEditor, ev.getX(), ev.getY());
      }
    });

    // Taint results
    this.taintResults = new JTextArea();
    taintResults.setText("Taint Results Placeholder!!!!");
    taintResults.setEditable(false);

    JSplitPane editorResultsSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestEditor, taintResults);
    editorResultsSplit.setResizeWeight(.5d);

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
  public byte[] getHttpMessage() {
    return this.requestEditor.getText().getBytes();
  }

  @Override
  public String getTaintSelection() {
    // NOTE: Below code assumes no overlapping highlights.
    Highlighter.Highlight[] highlights = requestEditor.getHighlighter().getHighlights();

    int numHighlights = highlights.length;
    if (requestEditor.getSelectedText() != null) {
      // For some reason, any currently selected (but not highlighted) text will be included in the
      // output of getHighlights.
      numHighlights--;
    }

    StringBuilder taintSelectionBuilder = new StringBuilder();
    for (int i = 0; i < numHighlights; i++) {
      int startOffset = highlights[i].getStartOffset();
      int endOffset = highlights[i].getEndOffset();
      if (endOffset - startOffset == 1) {  // One byte
        taintSelectionBuilder.append(startOffset);
      } else {
        taintSelectionBuilder.append(highlights[i].getStartOffset())
                .append(":")
                .append(highlights[i].getEndOffset());
      }
      if (i != highlights.length - 1) {
        taintSelectionBuilder.append(",");
      }
    }

    return taintSelectionBuilder.toString();
  }

  @Override
  public void displayTaintResults(String results) {
    this.taintResults.setText(results);
  }

  @Override
  public void registerButtonListener(ActionListener listener) {
    this.hostControlPanel.registerButtonListener(listener);
  }

  @Override
  public String getHttpServerHost() {
    return this.hostControlPanel.getHttpServerHost();
  }

  @Override
  public String getHttpServerPort() {
    return this.hostControlPanel.getHttpServerPort();
  }

  @Override
  public String getPandaServerHost() {
    return this.hostControlPanel.getPandaServerHost();
  }

  @Override
  public String getPandaServerPort() {
    return this.hostControlPanel.getPandaServerPort();
  }

  @Override
  public void alertUser(String message) {
    if (SwingUtilities.isEventDispatchThread()) { // If on EDT, must call directly (else will block).
      JOptionPane.showMessageDialog(this,
              message,
              "Alert",
              JOptionPane.WARNING_MESSAGE);
    } else {
      try {
        SwingUtilities.invokeAndWait(() ->
                JOptionPane.showMessageDialog(this,
                        message,
                        "Alert",
                        JOptionPane.WARNING_MESSAGE));
      } catch (InterruptedException | InvocationTargetException e) {
        e.printStackTrace(stderr);
      }
    }

  }

}
