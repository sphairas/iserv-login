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
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.net.imap.AuthenticatingIMAPClient;
import org.apache.commons.net.imap.IMAPSClient;

/**
 *
 * @author boris.heithecker
 */
public class IservRealm extends AppservRealm {

    static final String[] GROUPS = {"signees"}; //, "unitadmins"};
    private String host;
    private int port;
    private String endpoints;

    @Override
    protected void init(Properties props) throws BadRealmException, NoSuchRealmException {
        super.init(props);
        String h = props.getProperty("iserv.imap.host");
        String pt = props.getProperty("iserv.imap.port");
        String ep = props.getProperty("com.sun.appserv.iiop.endpoints");
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
            cl = new AuthenticatingIMAPClient(IMAPSClient.DEFAULT_PROTOCOL, true);
            cl.connect(h, p);
            host = h;
            port = p;
            if (ep != null && !ep.trim().isEmpty()) {
                this.endpoints = ep.trim();
            }
        } catch (IOException ex) {
            BadRealmException baex = new BadRealmException("Could not connect to: " + h + ":" + p, ex);
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
    public Enumeration getGroupNames(String string) throws InvalidOperationException, NoSuchUserException {
        return Collections.enumeration(Arrays.asList(GROUPS));
    }

    String getIservImapHost() {
        return host;
    }

    int getIservImapPort() {
        return port;
    }

    void addProperties(Properties props) {
        props.setProperty("com.sun.corba.ee.transport.ORBTCPTimeouts", "2000:60000:100");
        if (endpoints != null) {
            props.put("com.sun.appserv.iiop.endpoints", endpoints);
        }
    }
}
