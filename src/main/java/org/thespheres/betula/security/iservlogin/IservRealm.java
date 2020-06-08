/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.thespheres.betula.security.iservlogin;

import com.sun.appserv.security.AppservRealm;
import com.sun.enterprise.security.auth.realm.BadRealmException;
import com.sun.enterprise.security.auth.realm.InvalidOperationException;
import com.sun.enterprise.security.auth.realm.NoSuchRealmException;
import com.sun.enterprise.security.auth.realm.NoSuchUserException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import org.apache.commons.net.imap.AuthenticatingIMAPClient;
import org.apache.commons.net.imap.IMAPSClient;

/**
 *
 * @author boris.heithecker
 */
public class IservRealm extends AppservRealm {

    static final String DEFAULT_PASSWORD = "changeit";
    static final String[] GROUPS = {"signees"};
    private String host;
    private int port;
    private boolean endpointChecking;
    private String signeeSuffix;
    private String endpoints;
    private SSLContext ssl;

    @Override
    protected void init(Properties props) throws BadRealmException, NoSuchRealmException {
        super.init(props);
        final String h = props.getProperty("iserv.imap.host");
        final String pt = props.getProperty("iserv.imap.port");
        final String hv = props.getProperty("iserv.imap.checkEndpoint");
        final String suffix = props.getProperty("iserv.imap.signee-suffix");
        final String ep = props.getProperty("com.sun.appserv.iiop.endpoints");
        if (h == null || pt == null || h.isEmpty() || pt.isEmpty()) {
            throw new NoSuchRealmException("No iserv host and/or no iserv port provided.");
        }
        if (h.equals("${ISERV_IMAP_HOST}") || pt.equals("${ISERV_IMAP_PORT}")) {
            throw new NoSuchRealmException("ISERV_IMAP_HOST and/or ISERV_IMAP_PORT not set.");
        }
        int p;
        try {
            p = Integer.parseInt(pt);
        } catch (NumberFormatException e) {
            throw new BadRealmException("Invalid port number value provided: " + pt);
        }
        AuthenticatingIMAPClient cl = null;
        try {
            cl = new AuthenticatingIMAPClient(IMAPSClient.DEFAULT_PROTOCOL, true, getSSLContext());
            //Hostname verfications must be disabled because
            //server may be running on IServ as host machine
            final boolean checkEndpoint = Boolean.parseBoolean(hv);
            cl.setEndpointCheckingEnabled(checkEndpoint);
            cl.connect(h, p);
            host = h;
            port = p;
            signeeSuffix = (suffix == null || suffix.trim().isEmpty()) ? null : suffix.trim();
            endpointChecking = checkEndpoint;
            if (ep != null && !ep.trim().isEmpty()) {
                this.endpoints = ep.trim();
            }
        } catch (IOException ex) {
            final BadRealmException baex = new BadRealmException("Could not connect to: " + h + ":" + p, ex);
            Logger.getLogger(IservRealm.class.getName()).log(Level.SEVERE, baex.getMessage(), baex);
            throw baex;
        } finally {
            try {
                if (cl != null) {
                    cl.disconnect();
                }
            } catch (IOException ex) {
                throw new BadRealmException();
            }
        }
    }

    @Override
    public synchronized String getJAASContext() {
        return "iservRealm";
    }

    @Override
    public String getAuthType() {
        return "Iserv authentication realm";
    }

    @Override
    public Enumeration getGroupNames(final String string) throws InvalidOperationException, NoSuchUserException {
        return Collections.enumeration(Arrays.asList(GROUPS));
    }

    public String getIservImapHost() {
        return host;
    }

    public int getIservImapPort() {
        return port;
    }

    public boolean isEndpointChecking() {
        return endpointChecking;
    }

    public String getSigneeSuffix() {
        return signeeSuffix;
    }

    void addProperties(Properties props) {
        props.setProperty("com.sun.corba.ee.transport.ORBTCPTimeouts", "2000:60000:100");
        if (endpoints != null) {
            props.put("com.sun.appserv.iiop.endpoints", endpoints);
        }
    }

    SSLContext getSSLContext() throws BadRealmException {
        if (ssl == null) {
            try {
                final SSLContext ctx = SSLContext.getInstance("TLSv1.3");
                final KeyManagerFactory kstorefac = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                final Path kspath = Paths.get(System.getProperty("javax.net.ssl.keyStore"));
                final KeyStore kstore = KeyStore.getInstance(System.getProperty("javax.net.ssl.keyStoreType", KeyStore.getDefaultType()));
                kstore.load(Files.newInputStream(kspath, StandardOpenOption.READ), DEFAULT_PASSWORD.toCharArray());
                kstorefac.init(kstore, DEFAULT_PASSWORD.toCharArray());
                final KeyManager[] kms = kstorefac.getKeyManagers();
                final TrustManagerFactory tstorefac = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                final Path tspath = Paths.get(System.getProperty("javax.net.ssl.trustStore"));
                final KeyStore tstore = KeyStore.getInstance(System.getProperty("javax.net.ssl.trustStoreType", KeyStore.getDefaultType()));
                tstore.load(Files.newInputStream(tspath, StandardOpenOption.READ), DEFAULT_PASSWORD.toCharArray());
                tstorefac.init(tstore);
                ctx.init(kms, tstorefac.getTrustManagers(), new SecureRandom());
                ssl = ctx;
            } catch (final Exception ex) {
                throw new BadRealmException(ex);
            }
        }
        return ssl;
    }

}
