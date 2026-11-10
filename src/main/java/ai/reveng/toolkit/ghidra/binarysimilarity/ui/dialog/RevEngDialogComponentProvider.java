package ai.reveng.toolkit.ghidra.binarysimilarity.ui.dialog;

import docking.DialogComponentProvider;
import docking.widgets.label.GDLabel;
import generic.theme.GColor;
import generic.theme.GIcon;

import javax.swing.*;
import java.awt.*;

public class RevEngDialogComponentProvider extends DialogComponentProvider  {
    public RevEngDialogComponentProvider(String title, boolean isModal) {
        super(title, isModal);
    }

    protected JPanel createTitlePanel(String title) {
        return createTitlePanel(new GDLabel(title));
    }

    public static JPanel createTitlePanel(JLabel titleLabel) {
        titleLabel.setIcon(new GIcon("icon.reveng.mark.24"));
        titleLabel.setIconTextGap(8);
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD));

        JPanel titlePanel = new JPanel(new BorderLayout());
        titlePanel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, new GColor("color.border.reveng.title")),
                BorderFactory.createEmptyBorder(8, 12, 8, 12)));
        titlePanel.add(titleLabel, BorderLayout.CENTER);
        return titlePanel;
    }
}
