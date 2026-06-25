package com.clic2up;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.token.AbstractKeyStoreTokenConnection;

import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;

/**
 * Token PKCS#11 compatible JDK 9+ : DSS 6.0 initialise SunPKCS11 via une API
 * obsolète (JDK < 9) ; on utilise Provider.configure(String) à la place.
 */
public class Pkcs11TokenJDK17 extends AbstractKeyStoreTokenConnection {

    private final Provider provider;
    private final KeyStore.PasswordProtection password;

    public Pkcs11TokenJDK17(String pkcs11Driver, String pin) throws Exception {
        String config = "--name=clic2up-sign\nlibrary=" + pkcs11Driver;

        Provider base = Security.getProvider("SunPKCS11");
        if (base == null) {
            throw new DSSException("SunPKCS11 provider not available in this JVM");
        }

        this.provider = base.configure(config);
        Security.addProvider(this.provider);
        this.password = new KeyStore.PasswordProtection(pin.toCharArray());
    }

    @Override
    protected KeyStore getKeyStore() throws DSSException {
        try {
            KeyStore ks = KeyStore.getInstance("PKCS11", provider);
            ks.load(null, password.getPassword());
            return ks;
        } catch (Exception e) {
            throw new DSSException("Unable to load PKCS11 KeyStore: " + e.getMessage(), e);
        }
    }

    @Override
    protected KeyStore.PasswordProtection getKeyProtectionParameter() {
        return password;
    }

    @Override
    public void close() {
        try {
            Security.removeProvider(provider.getName());
        } catch (Exception e) {
            // cleanup best-effort
        }
    }
}
