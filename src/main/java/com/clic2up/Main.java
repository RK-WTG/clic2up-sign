package com.clic2up;

/**
 * Point d'entree principal pour clic2up-sign
 *
 * Usage:
 *   clic2up-sign server [--port 9876]
 *       Lance le serveur HTTP de signature
 *
 *   clic2up-sign signer-token <facture.xml> <driver.dll> <pin> <sortie.xml>
 *       Signe une facture avec un Token USB (PKCS11)
 *
 *   clic2up-sign signer-p12 <facture.xml> <certificat.p12> <motdepasse> <sortie.xml>
 *       Signe une facture avec un fichier PKCS12
 *
 *   clic2up-sign valider <facture_signee.xml>
 *       Valide la signature d'une facture
 *
 *   clic2up-sign lister-token <driver.dll> <pin>
 *       Liste les certificats dans un Token USB
 */
public class Main {

    private static final int DEFAULT_PORT = 9876;

    public static void main(String[] args) {
        if (args.length == 0) {
            // Par defaut, lance le serveur
            lancerServeur(DEFAULT_PORT);
            return;
        }

        String commande = args[0].toLowerCase();

        try {
            switch (commande) {
                case "server":
                    int port = DEFAULT_PORT;
                    if (args.length >= 3 && "--port".equals(args[1])) {
                        port = Integer.parseInt(args[2]);
                    }
                    lancerServeur(port);
                    break;

                case "preparer":
                    if (args.length < 3) {
                        System.err.println("Usage: preparer <input.xml> <output.xml>");
                        System.exit(1);
                    }
                    XmlUtils.preparerFacture(args[1], args[2]);
                    break;

                case "signer-p12":
                    if (args.length < 5) {
                        System.err.println("Usage: signer-p12 <facture.xml> <certificat.p12> <motdepasse> <sortie.xml>");
                        System.exit(1);
                    }
                    ElFatooraSignature.signerAvecPkcs12(args[1], args[2], args[3], args[4]);
                    break;

                case "signer-token":
                    if (args.length < 5) {
                        System.err.println("Usage: signer-token <facture.xml> <driver.dll> <pin> <sortie.xml>");
                        System.exit(1);
                    }
                    ElFatooraSignature.signerAvecPkcs11(args[1], args[2], args[3], args[4]);
                    break;

                case "valider":
                    if (args.length < 2) {
                        System.err.println("Usage: valider <facture_signee.xml>");
                        System.exit(1);
                    }
                    boolean valide = ElFatooraValidation.validerSignature(args[1]);
                    System.exit(valide ? 0 : 1);
                    break;

                case "lister-p12":
                    if (args.length < 3) {
                        System.err.println("Usage: lister-p12 <certificat.p12> <motdepasse>");
                        System.exit(1);
                    }
                    ElFatooraSignature.listerCertificatsPkcs12(args[1], args[2]);
                    break;

                case "lister-token":
                    if (args.length < 3) {
                        System.err.println("Usage: lister-token <driver.dll> <pin>");
                        System.exit(1);
                    }
                    ElFatooraSignature.listerCertificatsPkcs11(args[1], args[2]);
                    break;

                case "aide":
                case "help":
                case "-h":
                case "--help":
                    afficherAide();
                    break;

                default:
                    System.err.println("Commande inconnue: " + commande);
                    afficherAide();
                    System.exit(1);
            }
        } catch (Exception e) {
            System.err.println("Erreur: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    private static void lancerServeur(int port) {
        // Rediriger les logs vers un fichier (utile en mode GUI sans console)
        setupFileLogging();

        SigningServer server = new SigningServer(port);
        server.start();

        // Icone dans la barre des taches
        // Creer une Frame invisible pour forcer l'initialisation AWT en mode GUI
        java.awt.EventQueue.invokeLater(() -> {
            try {
                java.awt.Frame keepAlive = new java.awt.Frame("clic2up-sign");
                keepAlive.setUndecorated(true);
                keepAlive.setSize(0, 0);
                keepAlive.setType(java.awt.Window.Type.UTILITY);
                keepAlive.setVisible(true);

                SystemTrayManager tray = new SystemTrayManager(port, () -> {
                    System.out.println("\nArret du serveur depuis le tray...");
                    server.stop();
                });
                tray.setup();
            } catch (Exception e) {
                System.err.println("[TRAY] Erreur initialisation: " + e.getMessage());
                e.printStackTrace();
            }
        });

        // Shutdown hook pour arret propre
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("\nArret du serveur...");
            server.stop();
        }));
    }

    private static void setupFileLogging() {
        try {
            String logDir = System.getProperty("user.home");
            String logFile = logDir + java.io.File.separator + "clic2up-sign.log";
            java.io.PrintStream fileOut = new java.io.PrintStream(
                    new java.io.FileOutputStream(logFile, true));
            System.setOut(fileOut);
            System.setErr(fileOut);
            System.out.println("\n=== clic2up-sign demarre le " + new java.util.Date() + " ===");
        } catch (Exception e) {
            // Si on ne peut pas creer le fichier log, on continue sans
        }
    }

    private static void afficherAide() {
        System.out.println("╔══════════════════════════════════════════════════════════╗");
        System.out.println("║       clic2up-sign - Signature Electronique              ║");
        System.out.println("║     Conforme aux specifications ElFatoora / TRADENET     ║");
        System.out.println("╚══════════════════════════════════════════════════════════╝");
        System.out.println();
        System.out.println("Usage: clic2up-sign <commande> [options]");
        System.out.println();
        System.out.println("Commandes:");
        System.out.println();
        System.out.println("  server [--port 9876]");
        System.out.println("      Lance le serveur HTTP de signature (defaut: port 9876)");
        System.out.println();
        System.out.println("  signer-token <facture.xml> <driver.dll> <pin> <sortie.xml>");
        System.out.println("      Signe avec un Token USB (PKCS11)");
        System.out.println();
        System.out.println("  signer-p12 <facture.xml> <certificat.p12> <motdepasse> <sortie.xml>");
        System.out.println("      Signe avec un fichier PKCS12 (.p12 / .pfx)");
        System.out.println();
        System.out.println("  valider <facture_signee.xml>");
        System.out.println("      Valide la signature d'une facture");
        System.out.println();
        System.out.println("  lister-token <driver.dll> <pin>");
        System.out.println("      Liste les certificats du Token USB");
        System.out.println();
        System.out.println("  lister-p12 <certificat.p12> <motdepasse>");
        System.out.println("      Liste les certificats d'un fichier PKCS12");
        System.out.println();
        System.out.println("Sans commande: lance le serveur sur le port " + DEFAULT_PORT);
        System.out.println();
    }
}
