package com.clic2up;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;

/** Utilitaires XML pour ElFatoora. */
public class XmlUtils {

    /** Convertit le XML en "unpretty" (une seule ligne), obligatoire avant signature. */
    public static String toUnpretty(String xmlContent) {
        return xmlContent
                .replaceAll(">\\s+<", "><")
                .replaceAll("\\n", "")
                .replaceAll("\\r", "")
                .replaceAll("\\s{2,}", " ")
                .trim();
    }

    public static void preparerFacture(String inputPath, String outputPath) throws IOException {
        System.out.println("Preparation de la facture : " + inputPath);
        String content = new String(Files.readAllBytes(Paths.get(inputPath)), StandardCharsets.UTF_8);
        String unpretty = toUnpretty(content);
        verifierCaracteresSpeciaux(unpretty);
        Files.write(Paths.get(outputPath), unpretty.getBytes(StandardCharsets.UTF_8));
        System.out.println("Facture preparee : " + outputPath);
    }

    private static void verifierCaracteresSpeciaux(String content) {
        String[] caracteresProblematiques = {
                "\u00A0", "\u2019", "\u2018",
                "\u201C", "\u201D", "\u2013", "\u2014"
        };
        boolean problemeTrouve = false;
        for (String c : caracteresProblematiques) {
            if (content.contains(c)) {
                if (!problemeTrouve) {
                    System.out.println("\nATTENTION - Caracteres speciaux detectes :");
                    problemeTrouve = true;
                }
                System.out.println("  - Caractere Unicode " + String.format("U+%04X", (int) c.charAt(0)));
            }
        }
    }
}
