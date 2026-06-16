import sun.security.pkcs11.wrapper.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.io.ByteArrayInputStream;

/**
 * Lit les CERTIFICATS (objets publics) de chaque slot SANS LOGIN / SANS PIN.
 * But : determiner sur quel slot vit le certificat de signature QSign,
 * donc quel slot cibler pour la signature. Aucune tentative de PIN.
 */
public class SlotCertProbe {

    static final long CKA_CLASS = 0x00000000L;
    static final long CKA_LABEL = 0x00000003L;
    static final long CKA_VALUE = 0x00000011L;
    static final long CKA_ID    = 0x00000102L;
    static final long CKO_CERTIFICATE = 0x00000001L;
    static final long CKF_SERIAL_SESSION = 0x00000004L;

    public static void main(String[] args) throws Exception {
        String lib = args.length > 0 ? args[0]
                : "C:\\Program Files\\SafeNet\\Authentication\\SAC\\x64\\IDPrimePKCS1164.dll";
        System.out.println("Driver: " + lib);

        PKCS11 p11;
        try { p11 = PKCS11.getInstance(lib, "C_GetFunctionList", null, false); }
        catch (Throwable t) { p11 = PKCS11.getInstance(lib, "C_GetFunctionList", null, true); }

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        long[] slots = p11.C_GetSlotList(true);
        System.out.println("Slots avec token: " + slots.length);

        for (long slot : slots) {
            CK_TOKEN_INFO ti = p11.C_GetTokenInfo(slot);
            System.out.println("\n========== Slot " + slot + " : " + new String(ti.label).trim() + " ==========");
            long session = 0;
            try {
                // session lecture seule PUBLIQUE — pas de C_Login
                session = p11.C_OpenSession(slot, CKF_SERIAL_SESSION, null, null);

                CK_ATTRIBUTE[] tmpl = new CK_ATTRIBUTE[]{ new CK_ATTRIBUTE(CKA_CLASS, CKO_CERTIFICATE) };
                p11.C_FindObjectsInit(session, tmpl);
                long[] objs = p11.C_FindObjects(session, 50);
                p11.C_FindObjectsFinal(session);
                System.out.println("  Objets certificat (sans login): " + objs.length);

                for (long h : objs) {
                    CK_ATTRIBUTE[] read = new CK_ATTRIBUTE[]{
                            new CK_ATTRIBUTE(CKA_LABEL),
                            new CK_ATTRIBUTE(CKA_ID),
                            new CK_ATTRIBUTE(CKA_VALUE)
                    };
                    try {
                        p11.C_GetAttributeValue(session, h, read);
                        String label = read[0].getCharArray() != null ? new String(read[0].getCharArray()) : "";
                        byte[] id    = read[1].getByteArray();
                        byte[] der   = read[2].getByteArray();
                        System.out.println("    - CKA_LABEL: " + label);
                        System.out.println("      CKA_ID   : " + (id != null ? toHex(id) : "(null)"));
                        if (der != null && der.length > 0) {
                            X509Certificate x = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
                            System.out.println("      Subject  : " + x.getSubjectX500Principal());
                            System.out.println("      Issuer   : " + x.getIssuerX500Principal());
                            System.out.println("      Serial   : " + x.getSerialNumber().toString(16).toUpperCase());
                        }
                    } catch (Throwable e) {
                        System.out.println("    - (lecture objet impossible sans login: " + e.getMessage() + ")");
                    }
                }
            } catch (Throwable e) {
                System.out.println("  Slot illisible sans login: " + e.getMessage());
            } finally {
                if (session != 0) try { p11.C_CloseSession(session); } catch (Throwable ignore) {}
            }
        }
    }

    static String toHex(byte[] b) {
        StringBuilder s = new StringBuilder();
        for (byte x : b) s.append(String.format("%02X", x));
        return s.toString();
    }
}
