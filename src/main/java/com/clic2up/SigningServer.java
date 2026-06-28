package com.clic2up;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import io.javalin.Javalin;
import io.javalin.http.Context;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Map;

/** Serveur HTTP local appelé par le front clic2up pour signer via la clé USB. */
public class SigningServer {

    private static final String VERSION = "1.0";
    // Driver PKCS#11 : si le champ/param "driver"/"driverPath" est absent, on passe null
    // -> ElFatooraSignature.ouvrirToken essaie automatiquement les modules connus
    //    (IDPrimePKCS1164.dll puis eTPKCS11.dll). Le front peut toujours forcer un chemin.
    private static final Gson gson = new Gson();

    private final int port;
    private final String[] allowedOrigins;
    private Javalin app;

    public SigningServer(int port) {
        this.port = port;
        this.allowedOrigins = new String[]{
                "http://localhost:5173",
                "http://localhost:3000",
                "http://localhost:3009",
                "https://app.clic2up.com",
                "https://stg-app.clic2up.com",
                "https://api.clic2up.com"
        };
    }

    public void start() {
        app = Javalin.create(config -> {
            config.bundledPlugins.enableCors(cors -> {
                cors.addRule(rule -> {
                    for (String origin : allowedOrigins) {
                        rule.allowHost(origin);
                    }
                    rule.allowCredentials = false;
                });
            });
        });

        app.get("/status", this::handleStatus);
        app.get("/certificates", this::handleCertificates);
        app.post("/sign-hash", this::handleSignHash);
        app.post("/sign", this::handleSign);
        app.post("/validate", this::handleValidate);

        app.start(port);

        System.out.println("╔══════════════════════════════════════════════════════╗");
        System.out.println("║         clic2up-sign - Service de Signature          ║");
        System.out.println("╠══════════════════════════════════════════════════════╣");
        System.out.println("║  Status:  http://localhost:" + port + "/status              ║");
        System.out.println("║  Version: " + VERSION + "                                    ║");
        System.out.println("╚══════════════════════════════════════════════════════╝");
    }

    public void stop() {
        if (app != null) {
            app.stop();
        }
    }

    private void handleStatus(Context ctx) {
        ctx.json(Map.of("status", "running", "version", VERSION));
    }

    /** GET /certificates?pin=...&driver=... */
    private void handleCertificates(Context ctx) {
        String pin = ctx.queryParam("pin");
        String driver = ctx.queryParam("driver"); // null => fallback automatique

        if (pin == null || pin.isEmpty()) {
            ctx.status(400).json(Map.of("success", false, "error", "Le parametre 'pin' est requis"));
            return;
        }

        try {
            var certificates = ElFatooraSignature.listerCertificatsAvecChaine(driver, pin);
            ctx.json(Map.of("success", true, "certificates", certificates));
        } catch (Throwable e) {
            ctx.status(500).json(errorResponse("Erreur lors de la lecture des certificats", e));
        }
    }

    /** POST /sign-hash { data (base64 SignedInfo canonique), pin, certificate?, driverPath? } */
    private void handleSignHash(Context ctx) {
        JsonObject body = parseBody(ctx);
        String data = getJsonString(body, "data");
        String pin = getJsonString(body, "pin");
        String certificate = getJsonString(body, "certificate");
        String driver = getDriver(body);

        if (data == null || data.isEmpty()) {
            ctx.status(400).json(Map.of("success", false, "error", "Le champ 'data' est requis"));
            return;
        }
        if (pin == null || pin.isEmpty()) {
            ctx.status(400).json(Map.of("success", false, "error", "Le champ 'pin' est requis"));
            return;
        }

        try {
            String signatureValue = ElFatooraSignature.signerHashAvecToken(data, driver, pin, certificate);
            ctx.json(Map.of("success", true, "signatureValue", signatureValue));
        } catch (Throwable e) {
            ctx.status(500).json(errorResponse("Erreur lors de la signature du hash", e));
        }
    }

    /** POST /sign { xml, pin, driverPath? } */
    private void handleSign(Context ctx) {
        JsonObject body = parseBody(ctx);
        String xml = getJsonString(body, "xml");
        String pin = getJsonString(body, "pin");
        String driver = getDriver(body);

        if (xml == null || xml.isEmpty()) {
            ctx.status(400).json(Map.of("success", false, "error", "Le champ 'xml' est requis"));
            return;
        }
        if (pin == null || pin.isEmpty()) {
            ctx.status(400).json(Map.of("success", false, "error", "Le champ 'pin' est requis"));
            return;
        }

        try {
            String signedXml = ElFatooraSignature.signerXmlEnMemoire(xml, driver, pin);
            ctx.json(Map.of("success", true, "signedXml", signedXml));
        } catch (Throwable e) {
            Map<String, Object> err = new java.util.HashMap<>(errorResponse("Erreur lors de la signature", e));
            err.put("xmlPreview", xml.substring(0, Math.min(200, xml.length())));
            ctx.status(500).json(err);
        }
    }

    /** POST /validate { signedXml } */
    private void handleValidate(Context ctx) {
        JsonObject body = gson.fromJson(ctx.body(), JsonObject.class);
        String signedXml = getJsonString(body, "signedXml");

        if (signedXml == null || signedXml.isEmpty()) {
            ctx.status(400).json(Map.of("success", false, "error", "Le champ 'signedXml' est requis"));
            return;
        }

        try {
            boolean valid = ElFatooraValidation.validerSignatureEnMemoire(signedXml);
            ctx.json(Map.of("success", true, "valid", valid));
        } catch (Throwable e) {
            ctx.status(500).json(errorResponse("Erreur lors de la validation", e));
        }
    }

    // Un proxy peut insérer des \r\n dans les longues lignes du body JSON.
    private JsonObject parseBody(Context ctx) {
        return gson.fromJson(ctx.body().replaceAll("\\r?\\n\\s*", ""), JsonObject.class);
    }

    private String getDriver(JsonObject body) {
        return body.has("driverPath") && !body.get("driverPath").isJsonNull()
                ? body.get("driverPath").getAsString()
                : null; // null => fallback automatique cote ElFatooraSignature
    }

    private String getJsonString(JsonObject obj, String key) {
        if (obj == null || !obj.has(key) || obj.get(key).isJsonNull()) {
            return null;
        }
        return obj.get(key).getAsString();
    }

    private Map<String, Object> errorResponse(String message, Throwable e) {
        StringWriter sw = new StringWriter();
        e.printStackTrace(new PrintWriter(sw));
        ErreurSignature classe = classifier(e);
        Map<String, Object> r = new java.util.HashMap<>();
        r.put("success", false);
        r.put("errorCode", classe.code);   // code stable pour aiguillage front (ne pas traduire)
        r.put("message", classe.message);  // message FR pret a afficher par le front
        r.put("error", message);           // contexte technique
        r.put("errorMessage", e.getMessage() != null ? e.getMessage() : "Unknown error");
        r.put("stacktrace", sw.toString());
        return r;
    }

    /**
     * Categories d'erreur de signature. Le {@code code} est stable (utilise par le front
     * pour aiguiller : proposer le pilote, la cle, etc.) ; le {@code message} est le texte
     * FR pret a afficher.
     */
    private enum ErreurSignature {
        DRIVER_NOT_INSTALLED("DRIVER_NOT_INSTALLED",
                "Aucun pilote de signature n'a ete detecte sur ce poste. "
                        + "Veuillez installer le pilote de la cle (SafeNet Authentication Client)."),
        TOKEN_NOT_PRESENT("TOKEN_NOT_PRESENT",
                "Aucune cle USB de signature detectee. Veuillez brancher votre cle puis reessayer."),
        PIN_LOCKED("PIN_LOCKED",
                "Votre cle de signature est bloquee (trop de tentatives de code PIN). "
                        + "Veuillez la debloquer aupres de TunTrust."),
        PIN_INCORRECT("PIN_INCORRECT",
                "Code PIN incorrect. Veuillez reessayer "
                        + "(attention : la cle se bloque apres plusieurs erreurs)."),
        SIGN_ERROR("SIGN_ERROR",
                "Erreur lors de la signature. Veuillez verifier que la cle USB est branchee, "
                        + "que le pilote est installe, puis reessayer.");

        final String code;
        final String message;

        ErreurSignature(String code, String message) {
            this.code = code;
            this.message = message;
        }
    }

    /**
     * Classe une exception technique en categorie metier (pilote absent, cle non branchee,
     * PIN incorrect/bloque) en inspectant toute la chaine de causes.
     */
    private static ErreurSignature classifier(Throwable e) {
        StringBuilder sb = new StringBuilder();
        for (Throwable t = e; t != null; t = t.getCause()) {
            if (t.getMessage() != null) sb.append(' ').append(t.getMessage());
            sb.append(' ').append(t.getClass().getName());
        }
        String u = sb.toString().toUpperCase();

        if (u.contains("AUCUN MODULE PKCS#11") || u.contains("CONFIGURING SUNPKCS11")
                || u.contains("SUNPKCS11 PROVIDER NOT AVAILABLE") || u.contains("UNSATISFIEDLINK")
                || u.contains("CANNOT BE FOUND") || u.contains("NO SUCH FILE")) {
            return ErreurSignature.DRIVER_NOT_INSTALLED;
        }
        if (u.contains("AUCUNE CLE TROUVEE") || u.contains("CKR_TOKEN_NOT_PRESENT")
                || u.contains("TOKEN NOT PRESENT") || u.contains("CKR_DEVICE_REMOVED")
                || u.contains("CKR_SLOT_ID_INVALID")) {
            return ErreurSignature.TOKEN_NOT_PRESENT;
        }
        if (u.contains("PIN_LOCKED") || u.contains("CKR_PIN_LOCKED")) {
            return ErreurSignature.PIN_LOCKED;
        }
        if (u.contains("CKR_PIN") || u.contains("PIN_INCORRECT") || u.contains("FAILEDLOGIN")
                || u.contains("PIN")) {
            return ErreurSignature.PIN_INCORRECT;
        }
        return ErreurSignature.SIGN_ERROR;
    }
}
