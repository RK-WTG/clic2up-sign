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
    // Driver PKCS#11 du token TunTrust (Gemalto/Thales IDPrime, middleware SafeNet),
    // PAS eTPKCS11.dll. Surchargeable par le champ/param "driver"/"driverPath".
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
        String driver = ctx.queryParamAsClass("driver", String.class).getOrDefault(DEFAULT_DRIVER);

        if (pin == null || pin.isEmpty()) {
            ctx.status(400).json(Map.of("success", false, "error", "Le parametre 'pin' est requis"));
            return;
        }

        try {
            var certificates = ElFatooraSignature.listerCertificatsAvecChaine(driver, pin);
            ctx.json(Map.of("success", true, "certificates", certificates));
        } catch (Exception e) {
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
        } catch (Exception e) {
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
        } catch (Exception e) {
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
        } catch (Exception e) {
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
                : DEFAULT_DRIVER;
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
