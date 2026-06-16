package com.clic2up;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import io.javalin.Javalin;
import io.javalin.http.Context;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Map;

/**
 * Serveur HTTP local pour la signature electronique des factures.
 * Expose une API REST sur localhost que le frontend clic2up appelle.
 */
public class SigningServer {

    private static final String VERSION = "1.0.1";
    // Driver PKCS#11 du token de signature TunTrust (carte Gemalto/Thales IDPrime,
    // middleware SafeNet Authentication Client). PAS eTPKCS11.dll (= SafeNet eToken).
    // Le front peut surcharger via le param/champ "driver"/"driverPath".
    private static final String DEFAULT_DRIVER =
            "C:\\Program Files\\SafeNet\\Authentication\\SAC\\x64\\IDPrimePKCS1164.dll";
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
                "https://app.clic2up.com"
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

        // Routes
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

    /**
     * GET /status — Health check
     */
    private void handleStatus(Context ctx) {
        ctx.json(Map.of(
                "status", "running",
                "version", VERSION
        ));
    }

    /**
     * GET /certificates — Liste les certificats de la cle USB
     * Query params: pin (requis), driver (optionnel)
     */
    private void handleCertificates(Context ctx) {
        String pin = ctx.queryParam("pin");
        String driver = ctx.queryParamAsClass("driver", String.class).getOrDefault(DEFAULT_DRIVER);

        if (pin == null || pin.isEmpty()) {
            ctx.status(400).json(Map.of(
                    "success", false,
                    "error", "Le parametre 'pin' est requis"
            ));
            return;
        }

        try {
            var certificates = ElFatooraSignature.listerCertificatsAvecChaine(driver, pin);
            ctx.json(Map.of(
                    "success", true,
                    "certificates", certificates
            ));
        } catch (Exception e) {
            ctx.status(500).json(errorResponse("Erreur lors de la lecture des certificats", e));
        }
    }

    /**
     * POST /sign-hash — Signe les octets canoniques du SignedInfo (mode signHash).
     * Le XAdES est assemblé côté serveur clic2up ; le token ne fait que le RSA.
     * Body JSON: { data: string (base64), pin: string, certificate?: string (base64 DER), driverPath?: string }
     */
    private void handleSignHash(Context ctx) {
        // Nettoyer le body brut : un proxy peut inserer des \r\n dans les longues lignes
        String rawBody = ctx.body().replaceAll("\\r?\\n\\s*", "");
        JsonObject body = gson.fromJson(rawBody, JsonObject.class);

        String data = getJsonString(body, "data");
        String pin = getJsonString(body, "pin");
        String certificate = getJsonString(body, "certificate");
        String driver = body.has("driverPath") && !body.get("driverPath").isJsonNull()
                ? body.get("driverPath").getAsString()
                : DEFAULT_DRIVER;

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
            ctx.json(Map.of(
                    "success", true,
                    "signatureValue", signatureValue
            ));
        } catch (Exception e) {
            ctx.status(500).json(errorResponse("Erreur lors de la signature du hash", e));
        }
    }

    /**
     * POST /sign — Signe un XML avec la cle USB
     * Body JSON: { xml: string, pin: string, driverPath?: string }
     */
    private void handleSign(Context ctx) {
        // Nettoyer le body brut : Postman peut inserer des \r\n dans les longues lignes
        String rawBody = ctx.body().replaceAll("\\r?\\n\\s*", "");
        JsonObject body = gson.fromJson(rawBody, JsonObject.class);

        String xml = getJsonString(body, "xml");
        String pin = getJsonString(body, "pin");
        String driver = body.has("driverPath") && !body.get("driverPath").isJsonNull()
                ? body.get("driverPath").getAsString()
                : DEFAULT_DRIVER;

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
            ctx.json(Map.of(
                    "success", true,
                    "signedXml", signedXml
            ));
        } catch (Exception e) {
            Map<String, Object> err = new java.util.HashMap<>(errorResponse("Erreur lors de la signature", e));
            err.put("xmlPreview", xml.substring(0, Math.min(200, xml.length())));
            ctx.status(500).json(err);
        }
    }

    /**
     * POST /validate — Valide un XML signe
     * Body JSON: { signedXml: string }
     */
    private void handleValidate(Context ctx) {
        JsonObject body = gson.fromJson(ctx.body(), JsonObject.class);
        String signedXml = getJsonString(body, "signedXml");

        if (signedXml == null || signedXml.isEmpty()) {
            ctx.status(400).json(Map.of("success", false, "error", "Le champ 'signedXml' est requis"));
            return;
        }

        try {
            boolean valid = ElFatooraValidation.validerSignatureEnMemoire(signedXml);
            ctx.json(Map.of(
                    "success", true,
                    "valid", valid
            ));
        } catch (Exception e) {
            ctx.status(500).json(errorResponse("Erreur lors de la validation", e));
        }
    }

    private String getJsonString(JsonObject obj, String key) {
        if (obj == null || !obj.has(key) || obj.get(key).isJsonNull()) {
            return null;
        }
        return obj.get(key).getAsString();
    }

    private Map<String, Object> errorResponse(String message, Exception e) {
        StringWriter sw = new StringWriter();
        e.printStackTrace(new PrintWriter(sw));
        return Map.of(
                "success", false,
                "error", message,
                "errorMessage", e.getMessage() != null ? e.getMessage() : "Unknown error",
                "stacktrace", sw.toString()
        );
    }
}
