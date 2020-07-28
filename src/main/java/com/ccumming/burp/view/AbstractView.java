package com.ccumming.burp.view;

import javax.swing.JPanel;

/**
 * Abstract view class for any view(s) to extend.
 * Only used right now because alert dialog requires views to extend JPanel, so this fulfills that
 * requirement.
 */
public abstract class AbstractView extends JPanel implements IView {
}
