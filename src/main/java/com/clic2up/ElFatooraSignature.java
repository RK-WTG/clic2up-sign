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

/**
 * Classe de signature electronique XAdES-B pour ElFatoora
 * Conforme aux specifications TUNISIE TRADENET
 */
public class ElFatooraSignature {

    // Politique de signature — spec V3.0 (obligatoire en prod dès le 30/06/2026,
    // cf. Specifications_Techniques_Signature_Fournisseur_V3.0.pdf). Seul ce bloc
    // a changé entre V2 et V3.0.
    private static final String POLICY_OID = "urn:2.16.788.1.2.1.3";
    private static final String POLICY_DESCRIPTION = "Politique de Signature Electronique de Tunisie TradeNet";
    private static final String POLICY_URL = "https://www.tradenet.com.tn/Politique_Signature_Electronique_Tunisie_TradeNet.pdf";
    // SHA-256 (base64) du PDF de politique V3.0 — valeur figée par la spec. On la
    // force explicitement pour que le SigPolicyHash corresponde EXACTEMENT à ce
    // qu'attend le noyau TTN (sinon DSS tenterait de hacher le PDF téléchargé).
    private static final String POLICY_HASH_B64 = "ZKLu5TojntPu+bUfZyjaEDvkYsAh7eyyV+Hf8nUSQEE=";
    private static final String SIGNER_ROLE = "Fournisseur";

    /**
     * Signe un XML en memoire avec un Token USB (PKCS11)
     * C'est la methode principale appelee par le serveur HTTP.
     *
     * @param xmlContent   Contenu XML de la facture
     * @param pkcs11Driver Chemin vers le driver PKCS11 (.dll)
     * @param pin          Code PIN du Token
     * @return XML signe complet
     */
    public static String signerXmlEnMemoire(String xmlContent, String pkcs11Driver, String pin) throws Exception {
        // Nettoyer le XML : retirer TOUS les retours a la ligne et espaces excessifs
        String cleanXml = xmlContent
                .replace("\r\n", "")
                .replace("\r", "")
                .replace("\n", "")
                .replaceAll(">\\s+<", "><")
                .trim();

        // Retirer le placeholder de signature s'il existe
        cleanXml = retirerPlaceholderSignature(cleanXml);

        try (Pkcs11TokenJDK17 token = new Pkcs11TokenJDK17(pkcs11Driver, pin)) {

            List<DSSPrivateKeyEntry> keys = token.getKeys();
            if (keys.isEmpty()) {
                throw new RuntimeException("Aucune cle trouvee dans le Token USB");
            }
            DSSPrivateKeyEntry privateKey = keys.get(0);

            return signerEnMemoire(token, privateKey, cleanXml);
        }
    }

    /**
     * Signe une empreinte (mode signHash) avec un Token USB (PKCS11).
     *
     * Le serveur clic2up (NestJS) assemble lui-même tout le XAdES-B ElFatoora et
     * nous transmet uniquement les OCTETS CANONIQUES du SignedInfo (base64) ; le
     * token se contente du RSA. DSS hache ces octets (SHA-256) puis signe → la
     * signatureValue retournée se vérifie en RSA-SHA256 contre le SignedInfo, ce
     * qu'attend l'assembleur NestJS. Ne PAS passer un digest déjà calculé (double-hash).
     *
     * @param dataBase64     octets canoniques du SignedInfo, encodés base64
     * @param pkcs11Driver   chemin du driver PKCS11 (.dll)
     * @param pin            code PIN du Token
     * @param certificateB64 certificat signataire (DER base64) pour sélectionner la
     *                       bonne clé ; si null/vide, la première clé est utilisée
     * @return signatureValue RSA (base64)
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

            ToBeSigned toBeSigned = new ToBeSigned(data);
            SignatureValue signatureValue = token.sign(toBeSigned, DigestAlgorithm.SHA256, privateKey);
            return Base64.getEncoder().encodeToString(signatureValue.getValue());
        }
    }

    /**
     * Sélectionne la clé dont le certificat correspond au DER fourni ; à défaut la
     * première (l'ordre des clés PKCS#11 est stable pour un même token/driver).
     */
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

    /**
     * Liste les certificats AVEC le DER base64 du signataire et de sa chaîne.
     * Le back NestJS a besoin de la chaîne (signataire en tête) pour construire le
     * bloc KeyInfo et SigningCertificateV2 du XAdES.
     */
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
                // garantir le signataire en tête de chaîne
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

    /**
     * Signe une facture avec un fichier PKCS12 (sortie fichier)
     */
    public static void signerAvecPkcs12(String factureXmlPath, String certificatPath,
                                         String motDePasse, String outputPath) throws Exception {
        try (Pkcs12SignatureToken token = new Pkcs12SignatureToken(
                new FileInputStream(certificatPath),
                new KeyStore.PasswordProtection(motDePasse.toCharArray()))) {

            List<DSSPrivateKeyEntry> keys = token.getKeys();
            if (keys.isEmpty()) {
                throw new RuntimeException("Aucune cle trouvee dans le fichier PKCS12");
            }
            DSSPrivateKeyEntry privateKey = keys.get(0);
            signerFacture(token, privateKey, factureXmlPath, outputPath);
        }
    }

    /**
     * Signe une facture avec un Token USB (sortie fichier)
     */
    public static void signerAvecPkcs11(String factureXmlPath, String pkcs11Driver,
                                         String pin, String outputPath) throws Exception {
        try (Pkcs11TokenJDK17 token = new Pkcs11TokenJDK17(pkcs11Driver, pin)) {

            List<DSSPrivateKeyEntry> keys = token.getKeys();
            if (keys.isEmpty()) {
                throw new RuntimeException("Aucune cle trouvee dans le Token USB");
            }
            DSSPrivateKeyEntry privateKey = keys.get(0);
            signerFacture(token, privateKey, factureXmlPath, outputPath);
        }
    }

    /**
     * Methode interne de signature en memoire — retourne le XML signe
     */
    private static String signerEnMemoire(SignatureTokenConnection token,
                                           DSSPrivateKeyEntry privateKey,
                                           String xmlContent) throws Exception {
        DSSDocument factureXml = new InMemoryDocument(xmlContent.getBytes("UTF-8"), "facture.xml", MimeTypeEnum.XML);

        XAdESSignatureParameters params = creerParametresSignature(privateKey);

        CommonCertificateVerifier verifier = new CommonCertificateVerifier();
        XAdESService service = new XAdESService(verifier);

        ToBeSigned dataToSign = service.getDataToSign(factureXml, params);
        SignatureValue signatureValue = token.sign(dataToSign, params.getDigestAlgorithm(), privateKey);
        DSSDocument documentSigne = service.signDocument(factureXml, params, signatureValue);

        // Lire le document signe en String
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

    /**
     * Methode interne de signature avec sortie fichier
     */
    private static void signerFacture(SignatureTokenConnection token,
                                       DSSPrivateKeyEntry privateKey,
                                       String factureXmlPath,
                                       String outputPath) throws Exception {
        DSSDocument factureXml = new FileDocument(factureXmlPath);

        XAdESSignatureParameters params = creerParametresSignature(privateKey);
        CommonCertificateVerifier verifier = new CommonCertificateVerifier();
        XAdESService service = new XAdESService(verifier);

        ToBeSigned dataToSign = service.getDataToSign(factureXml, params);
        SignatureValue signatureValue = token.sign(dataToSign, params.getDigestAlgorithm(), privateKey);
        DSSDocument documentSigne = service.signDocument(factureXml, params, signatureValue);

        documentSigne.save(outputPath);
        System.out.println("Facture signee avec succes : " + outputPath);
    }

    /**
     * Cree les parametres de signature conformes aux specs ElFatoora
     */
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
        policy.setQualifier(ObjectIdentifierQualifier.OID_AS_URN); // → Qualifier="OIDAsURN" (V3.0)
        policy.setDescription(POLICY_DESCRIPTION);
        policy.setDigestAlgorithm(DigestAlgorithm.SHA256);
        policy.setDigestValue(Base64.getDecoder().decode(POLICY_HASH_B64));
        policy.setSpuri(POLICY_URL);
        params.bLevel().setSignaturePolicy(policy);

        params.bLevel().setClaimedSignerRoles(Arrays.asList(SIGNER_ROLE));

        return params;
    }

    /**
     * Retire le bloc placeholder <ds:Signature> du XML si present
     */
    private static String retirerPlaceholderSignature(String xml) {
        // Retirer le bloc ds:Signature placeholder genere par teifXmlGenerator.ts
        return xml.replaceAll(
                "\\s*<ds:Signature[^>]*>.*?</ds:Signature>\\s*",
                ""
        );
    }

    /**
     * Liste les certificats avec leurs infos (pour l'API REST)
     */
    public static List<Map<String, String>> listerCertificatsInfo(String pkcs11Driver, String pin) throws Exception {
        List<Map<String, String>> result = new ArrayList<>();

        try (Pkcs11TokenJDK17 token = new Pkcs11TokenJDK17(pkcs11Driver, pin)) {

            List<DSSPrivateKeyEntry> keys = token.getKeys();

            for (int i = 0; i < keys.size(); i++) {
                CertificateToken cert = keys.get(i).getCertificate();
                Map<String, String> info = new LinkedHashMap<>();
                info.put("index", String.valueOf(i));
                info.put("subject", cert.getSubject().getRFC2253());
                info.put("issuer", cert.getIssuer().getRFC2253());
                info.put("validFrom", cert.getNotBefore().toString());
                info.put("validTo", cert.getNotAfter().toString());
                info.put("serialNumber", cert.getSerialNumber().toString());
                info.put("algorithm", cert.getPublicKey().getAlgorithm());
                result.add(info);
            }
        }

        return result;
    }

    /**
     * Liste les certificats PKCS12 (console)
     */
    public static void listerCertificatsPkcs12(String certificatPath, String motDePasse) throws Exception {
        try (Pkcs12SignatureToken token = new Pkcs12SignatureToken(
                new FileInputStream(certificatPath),
                new KeyStore.PasswordProtection(motDePasse.toCharArray()))) {

            List<DSSPrivateKeyEntry> keys = token.getKeys();
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

    /**
     * Liste les certificats PKCS11 (console)
     */
    public static void listerCertificatsPkcs11(String pkcs11Driver, String pin) throws Exception {
        try (Pkcs11TokenJDK17 token = new Pkcs11TokenJDK17(pkcs11Driver, pin)) {

            List<DSSPrivateKeyEntry> keys = token.getKeys();
            System.out.println("Certificats trouves dans le Token : " + keys.size());

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
}
