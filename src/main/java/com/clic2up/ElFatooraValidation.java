package com.clic2up;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

/** Validation de signature XAdES (DSS) pour ElFatoora. */
public class ElFatooraValidation {

    public static boolean validerSignature(String cheminFichier) throws Exception {
        return validerDocument(new FileDocument(cheminFichier));
    }

    public static boolean validerSignatureEnMemoire(String xmlContent) throws Exception {
        DSSDocument document = new InMemoryDocument(
                xmlContent.getBytes("UTF-8"), "facture_signee.xml", MimeTypeEnum.XML);
        return validerDocument(document);
    }

    private static boolean validerDocument(DSSDocument document) throws Exception {
        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);

        CommonCertificateVerifier verifier = new CommonCertificateVerifier();
        verifier.setCheckRevocationForUntrustedChains(false); // offline : pas d'appel OCSP/CRL
        validator.setCertificateVerifier(verifier);

        Reports reports = validator.validateDocument();
        SimpleReport simpleReport = reports.getSimpleReport();
        boolean valide = simpleReport.isValid(simpleReport.getFirstSignatureId());

        System.out.println("=== Resultat de validation ===");
        System.out.println("Signature ID: " + simpleReport.getFirstSignatureId());
        System.out.println("Valide: " + valide);
        System.out.println("Indication: " + simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        return valide;
    }
}
