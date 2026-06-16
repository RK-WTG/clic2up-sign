import sun.security.pkcs11.wrapper.*;

/**
 * Lecture SANS LOGIN des flags du token (C_GetTokenInfo).
 * Ne consomme aucune tentative de PIN — purement informatif.
 */
public class TokenInfoProbe {

    // Flags PKCS#11 relatifs au PIN utilisateur
    static final long CKF_TOKEN_INITIALIZED  = 0x00000400L;
    static final long CKF_USER_PIN_INITIALIZED= 0x00000008L;
    static final long CKF_LOGIN_REQUIRED      = 0x00000004L;
    static final long CKF_USER_PIN_COUNT_LOW  = 0x00010000L;
    static final long CKF_USER_PIN_FINAL_TRY  = 0x00020000L;
    static final long CKF_USER_PIN_LOCKED     = 0x00040000L;
    static final long CKF_SO_PIN_COUNT_LOW    = 0x00100000L;
    static final long CKF_SO_PIN_FINAL_TRY    = 0x00200000L;
    static final long CKF_SO_PIN_LOCKED       = 0x00400000L;

    public static void main(String[] args) throws Exception {
        String lib = args.length > 0 ? args[0]
                : "C:\\Program Files\\SafeNet\\Authentication\\SAC\\x64\\IDPrimePKCS1164.dll";
        System.out.println("Driver: " + lib);

        PKCS11 p11 = null;
        try {
            p11 = PKCS11.getInstance(lib, "C_GetFunctionList", null, false);
        } catch (Throwable t) {
            // module deja initialise par SAC -> on n'initialise pas
            p11 = PKCS11.getInstance(lib, "C_GetFunctionList", null, true);
        }

        long[] slots = p11.C_GetSlotList(true); // true = token present
        System.out.println("Slots avec token: " + slots.length);
        for (long slot : slots) {
            CK_TOKEN_INFO ti = p11.C_GetTokenInfo(slot);
            String label = new String(ti.label).trim();
            String serial = new String(ti.serialNumber).trim();
            long f = ti.flags;
            System.out.println("\n=== Slot " + slot + " ===");
            System.out.println("  Label        : " + label);
            System.out.println("  Serial token : " + serial);
            System.out.println("  flags        : 0x" + Long.toHexString(f));
            System.out.println("  Tentatives utilisateur restantes (champs IDPrime) :");
            // certains champs renseignes selon le driver
            try { System.out.println("    ulMaxPinLen=" + ti.ulMaxPinLen + " ulMinPinLen=" + ti.ulMinPinLen); } catch (Throwable ignore) {}
            System.out.println("  -- Etat PIN utilisateur --");
            System.out.println("    USER_PIN_LOCKED     : " + ((f & CKF_USER_PIN_LOCKED)!=0 ? "OUI (VERROUILLE)" : "non"));
            System.out.println("    USER_PIN_FINAL_TRY  : " + ((f & CKF_USER_PIN_FINAL_TRY)!=0 ? "OUI (derniere tentative !)" : "non"));
            System.out.println("    USER_PIN_COUNT_LOW  : " + ((f & CKF_USER_PIN_COUNT_LOW)!=0 ? "OUI (au moins 1 echec)" : "non"));
            System.out.println("    USER_PIN_INITIALIZED: " + ((f & CKF_USER_PIN_INITIALIZED)!=0 ? "oui" : "non"));
            System.out.println("  -- Etat PIN admin/SO --");
            System.out.println("    SO_PIN_LOCKED       : " + ((f & CKF_SO_PIN_LOCKED)!=0 ? "OUI" : "non"));
            System.out.println("    SO_PIN_FINAL_TRY    : " + ((f & CKF_SO_PIN_FINAL_TRY)!=0 ? "OUI" : "non"));
            System.out.println("    SO_PIN_COUNT_LOW    : " + ((f & CKF_SO_PIN_COUNT_LOW)!=0 ? "OUI" : "non"));
        }
    }
}
