package com.clic2up;

import eu.europa.esig.dss.enumerations.*;
import eu.europa.esig.dss.model.*;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.token.*;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.xades.*;
import eu.europa.esig.dss.xades.signature.*;

import java.io.*;
import java.security.KeyStore;
import java.util.*;

/** Signature XAdES-B ElFatoora via token PKCS#11 (USB) ou fichier PKCS#12. */
public class ElFatooraSignature {

    // Politique de signature V3.0 (obligatoire en prod dès le 30/06/2026,
    // Specifications_Techniques_Signature_Fournisseur_V3.0.pdf). Seul ce bloc change vs V2.
    private static final String POLICY_OID = "urn:2.16.788.1.2.1.3";
    private static final String POLICY_DESCRIPTION = "Politique de Signature Electronique de Tunisie TradeNet";
    private static final String POLICY_URL = "https://www.tradenet.com.tn/Politique_Signature_Electronique_Tunisie_TradeNet.pdf";
    // SHA-256 du PDF de politique, forcé pour matcher la valeur attendue par le noyau TTN.
    private static final String POLICY_HASH_B64 = "ZKLu5TojntPu+bUfZyjaEDvkYsAh7eyyV+Hf8nUSQEE=";
    private static final String SIGNER_ROLE = "Fournisseur";

    /** Signe un XML complet en mémoire avec un token USB (DSS full XAdES). */
    public static String signerXmlEnMemoire(String xmlContent, String pkcs11Driver, String pin) throws Exception {
        String cleanXml = xmlContent
                .replace("\r\n", "")
                .replace("\r", "")
                .replace("\n", "")
                .replaceAll(">\\s+<", "><")
                .trim();
        cleanXml = retirerPlaceholderSignature(cleanXml);

        try (Pkcs11TokenJDK17 token = new Pkcs11TokenJDK17(pkcs11Driver, pin)) {
            List<DSSPrivateKeyEntry> keys = token.getKeys();
            if (keys.isEmpty()) {
                throw new RuntimeException("Aucune cle trouvee dans le Token USB");
            }
            return signerEnMemoire(token, keys.get(0), cleanXml);
        }
    }

    /**
     * Mode signHash : le serveur NestJS assemble le XAdES et transmet les octets
     * canoniques du SignedInfo (base64) ; le token ne fait que le RSA (DSS hache
     * puis signe). Ne PAS passer un digest déjà calculé (double-hash).
     */
    public static String signerHashAvecToken(String dataBase64, String pkcs11Driver,
                                              String pin, String certificateB64) throws Exception {
        byte[] data = Base64.getDecoder().decode(dataBase64);
        try (Pkcs11TokenJDK17 token = new Pkcs11TokenJDK17(pkcs11Driver, pin)) {
            List<DSSPrivateKeyEntry> keys = token.getKeys();
            if (keys.isEmpty()) {
                throw new RuntimeException("Aucune cle trouvee dans le Token USB");
            }
            DSSPrivateKeyEntry privateKey = selectionnerCle(keys, certificateB64);
            SignatureValue signatureValue = token.sign(new ToBeSigned(data), DigestAlgorithm.SHA256, privateKey);
            return Base64.getEncoder().encodeToString(signatureValue.getValue());
        }
    }

    /** Sélectionne la clé dont le certificat correspond au DER fourni, sinon la première. */
    private static DSSPrivateKeyEntry selectionnerCle(List<DSSPrivateKeyEntry> keys,
                                                      String certificateB64) throws Exception {
        if (certificateB64 != null && !certificateB64.isEmpty()) {
            byte[] target = Base64.getDecoder().decode(certificateB64);
            for (DSSPrivateKeyEntry k : keys) {
                if (Arrays.equals(k.getCertificate().getEncoded(), target)) {
                    return k;
                }
            }
        }
        return keys.get(0);
    }

    /** Liste les certificats avec le DER base64 du signataire et de sa chaîne (KeyInfo/SigningCertificateV2). */
    public static List<Map<String, Object>> listerCertificatsAvecChaine(String pkcs11Driver, String pin) throws Exception {
        List<Map<String, Object>> result = new ArrayList<>();
        try (Pkcs11TokenJDK17 token = new Pkcs11TokenJDK17(pkcs11Driver, pin)) {
            List<DSSPrivateKeyEntry> keys = token.getKeys();
            for (int i = 0; i < keys.size(); i++) {
                DSSPrivateKeyEntry key = keys.get(i);
                CertificateToken cert = key.getCertificate();
                String signerB64 = Base64.getEncoder().encodeToString(cert.getEncoded());

                List<String> chain = new ArrayList<>();
                CertificateToken[] certChain = key.getCertificateChain();
                if (certChain != null) {
                    for (CertificateToken c : certChain) {
                        chain.add(Base64.getEncoder().encodeToString(c.getEncoded()));
                    }
                }
                if (chain.isEmpty() || !chain.get(0).equals(signerB64)) {
                    chain.add(0, signerB64);
                }

                Map<String, Object> info = new LinkedHashMap<>();
                info.put("index", i);
                info.put("subject", cert.getSubject().getRFC2253());
                info.put("issuer", cert.getIssuer().getRFC2253());
                info.put("validFrom", cert.getNotBefore().toString());
                info.put("validTo", cert.getNotAfter().toString());
                info.put("serialNumber", cert.getSerialNumber().toString());
                info.put("certificate", signerB64);
                info.put("certificateChain", chain);
                result.add(info);
            }
        }
        return result;
    }

    /** Signe une facture (fichier) avec un fichier PKCS#12. */
    public static void signerAvecPkcs12(String factureXmlPath, String certificatPath,
                                         String motDePasse, String outputPath) throws Exception {
        try (Pkcs12SignatureToken token = new Pkcs12SignatureToken(
                new FileInputStream(certificatPath),
                new KeyStore.PasswordProtection(motDePasse.toCharArray()))) {
            List<DSSPrivateKeyEntry> keys = token.getKeys();
            if (keys.isEmpty()) {
                throw new RuntimeException("Aucune cle trouvee dans le fichier PKCS12");
            }
            signerFacture(token, keys.get(0), factureXmlPath, outputPath);
        }
    }

    /** Signe une facture (fichier) avec un token USB. */
    public static void signerAvecPkcs11(String factureXmlPath, String pkcs11Driver,
                                         String pin, String outputPath) throws Exception {
        try (Pkcs11TokenJDK17 token = new Pkcs11TokenJDK17(pkcs11Driver, pin)) {
            List<DSSPrivateKeyEntry> keys = token.getKeys();
            if (keys.isEmpty()) {
                throw new RuntimeException("Aucune cle trouvee dans le Token USB");
            }
            signerFacture(token, keys.get(0), factureXmlPath, outputPath);
        }
    }

    private static String signerEnMemoire(SignatureTokenConnection token,
                                           DSSPrivateKeyEntry privateKey,
                                           String xmlContent) throws Exception {
        DSSDocument factureXml = new InMemoryDocument(xmlContent.getBytes("UTF-8"), "facture.xml", MimeTypeEnum.XML);
        XAdESSignatureParameters params = creerParametresSignature(privateKey);
        XAdESService service = new XAdESService(new CommonCertificateVerifier());

        ToBeSigned dataToSign = service.getDataToSign(factureXml, params);
        SignatureValue signatureValue = token.sign(dataToSign, params.getDigestAlgorithm(), privateKey);
        DSSDocument documentSigne = service.signDocument(factureXml, params, signatureValue);

        try (InputStream is = documentSigne.openStream();
             ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192];
            int len;
            while ((len = is.read(buffer)) != -1) {
                baos.write(buffer, 0, len);
            }
            return baos.toString("UTF-8");
        }
    }

    private static void signerFacture(SignatureTokenConnection token,
                                       DSSPrivateKeyEntry privateKey,
                                       String factureXmlPath,
                                       String outputPath) throws Exception {
        DSSDocument factureXml = new FileDocument(factureXmlPath);
        XAdESSignatureParameters params = creerParametresSignature(privateKey);
        XAdESService service = new XAdESService(new CommonCertificateVerifier());

        ToBeSigned dataToSign = service.getDataToSign(factureXml, params);
        SignatureValue signatureValue = token.sign(dataToSign, params.getDigestAlgorithm(), privateKey);
        DSSDocument documentSigne = service.signDocument(factureXml, params, signatureValue);

        documentSigne.save(outputPath);
        System.out.println("Facture signee avec succes : " + outputPath);
    }

    /** Paramètres de signature conformes aux specs ElFatoora V3.0. */
    private static XAdESSignatureParameters creerParametresSignature(DSSPrivateKeyEntry privateKey) {
        XAdESSignatureParameters params = new XAdESSignatureParameters();
        params.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        params.setSignaturePackaging(SignaturePackaging.ENVELOPED);
        params.setDigestAlgorithm(DigestAlgorithm.SHA256);
        params.setSigningCertificate(privateKey.getCertificate());
        params.setCertificateChain(privateKey.getCertificateChain());
        params.bLevel().setSigningDate(new Date());

        Policy policy = new Policy();
        policy.setId(POLICY_OID);
        policy.setQualifier(ObjectIdentifierQualifier.OID_AS_URN); // => Qualifier="OIDAsURN"
        policy.setDescription(POLICY_DESCRIPTION);
        policy.setDigestAlgorithm(DigestAlgorithm.SHA256);
        policy.setDigestValue(Base64.getDecoder().decode(POLICY_HASH_B64));
        policy.setSpuri(POLICY_URL);
        params.bLevel().setSignaturePolicy(policy);
        params.bLevel().setClaimedSignerRoles(Arrays.asList(SIGNER_ROLE));
        return params;
    }

    private static String retirerPlaceholderSignature(String xml) {
        return xml.replaceAll("\\s*<ds:Signature[^>]*>.*?</ds:Signature>\\s*", "");
    }

    /** Liste console des certificats d'un fichier PKCS#12. */
    public static void listerCertificatsPkcs12(String certificatPath, String motDePasse) throws Exception {
        try (Pkcs12SignatureToken token = new Pkcs12SignatureToken(
                new FileInputStream(certificatPath),
                new KeyStore.PasswordProtection(motDePasse.toCharArray()))) {
            afficherCertificats(token.getKeys());
        }
    }

    /** Liste console des certificats d'un token USB. */
    public static void listerCertificatsPkcs11(String pkcs11Driver, String pin) throws Exception {
        try (Pkcs11TokenJDK17 token = new Pkcs11TokenJDK17(pkcs11Driver, pin)) {
            afficherCertificats(token.getKeys());
        }
    }

    private static void afficherCertificats(List<DSSPrivateKeyEntry> keys) {
        System.out.println("Certificats trouves : " + keys.size());
        for (int i = 0; i < keys.size(); i++) {
            CertificateToken cert = keys.get(i).getCertificate();
            System.out.println("\n--- Certificat " + (i + 1) + " ---");
            System.out.println("Sujet: " + cert.getSubject().getRFC2253());
            System.out.println("Emetteur: " + cert.getIssuer().getRFC2253());
            System.out.println("Valide du: " + cert.getNotBefore());
            System.out.println("Valide jusqu'au: " + cert.getNotAfter());
            System.out.println("Numero de serie: " + cert.getSerialNumber());
        }
    }
}
