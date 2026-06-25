package com.clic2up;

import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.InputStream;
import java.net.URI;
import java.util.logging.Logger;
import javax.imageio.ImageIO;

/**
 * Gere l'icone dans la barre des taches (system tray) Windows.
 * Affiche un menu contextuel avec statut, acces navigateur et quitter.
 */
public class SystemTrayManager {

    private static final Logger LOG = Logger.getLogger(SystemTrayManager.class.getName());
    private static final String APP_NAME = "clic2up-sign";
    private TrayIcon trayIcon;
    private final int port;
    private final Runnable onQuit;

    public SystemTrayManager(int port, Runnable onQuit) {
        this.port = port;
        this.onQuit = onQuit;
    }

    public void setup() {
        try {
            Toolkit.getDefaultToolkit();

            if (!SystemTray.isSupported()) {
                LOG.warning("[TRAY] System tray non supporte sur ce systeme");
                return;
            }

            SystemTray tray = SystemTray.getSystemTray();
            Image icon = createIcon();

            PopupMenu popup = new PopupMenu();

            MenuItem titleItem = new MenuItem("clic2up-sign v1.0");
            titleItem.setEnabled(false);
            popup.add(titleItem);

            popup.addSeparator();

            MenuItem statusItem = new MenuItem("Actif sur le port " + port);
            statusItem.setEnabled(false);
            popup.add(statusItem);

            popup.addSeparator();

            MenuItem openItem = new MenuItem("Ouvrir le statut");
            openItem.addActionListener(e -> ouvrirNavigateur());
            popup.add(openItem);

            popup.addSeparator();

            MenuItem quitItem = new MenuItem("Quitter");
            quitItem.addActionListener(e -> {
                if (onQuit != null) {
                    onQuit.run();
                }
                tray.remove(trayIcon);
                System.exit(0);
            });
            popup.add(quitItem);

            trayIcon = new TrayIcon(icon, APP_NAME + " - Port " + port, popup);
            trayIcon.setImageAutoSize(true);
            trayIcon.addActionListener(e -> ouvrirNavigateur());

            tray.add(trayIcon);
            LOG.info("[TRAY] Icone ajoutee dans la barre des taches");

        } catch (Exception e) {
            LOG.severe("[TRAY] Erreur: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private void ouvrirNavigateur() {
        try {
            Desktop.getDesktop().browse(new URI("http://localhost:" + port + "/status"));
        } catch (Exception ex) {
            LOG.warning("[TRAY] Impossible d'ouvrir le navigateur: " + ex.getMessage());
        }
    }

    private Image createIcon() {
        try (InputStream is = getClass().getResourceAsStream("/clic2up-sign.png")) {
            if (is != null) {
                return ImageIO.read(is);
            }
        } catch (Exception e) {
            LOG.warning("[TRAY] Impossible de charger l'icone: " + e.getMessage());
        }
        BufferedImage img = new BufferedImage(64, 64, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g = img.createGraphics();
        g.setColor(new Color(37, 99, 235));
        g.fillOval(2, 2, 60, 60);
        g.setColor(Color.WHITE);
        g.setFont(new Font("Arial", Font.BOLD, 24));
        g.drawString("C2", 14, 40);
        g.dispose();
        return img;
    }
}
