/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.thespheres.betula.security.iservlogin;

import com.sun.appserv.security.AppservCertificateLoginModule;
import java.util.Arrays;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.security.auth.login.LoginException;

/**
 *
 * @author boris.heithecker
 */
public class AdminCertificateLoginModule extends AppservCertificateLoginModule {
    
    private final boolean authenticateUnknownTrustedPrincipals;
    
    public AdminCertificateLoginModule() {
        String prop = System.getProperty(Constants.SYSTEMPROP_AUTHENTICATE_UNKNOWN_TRUSTED_X500PRINCIPALS);
        this.authenticateUnknownTrustedPrincipals = prop != null && prop.toLowerCase().equals("true");
    }
    
    @Override
    protected void authenticateUser() throws LoginException {
        String principal = getX500Principal().getName();
        String[] groups = null; //X500Cache.getCached(principal);
        if (groups == null) {
            try {
                Properties props = new Properties();
                props.setProperty("com.sun.corba.ee.transport.ORBTCPTimeouts", "2000:60000:100");
                IservLogin lb = (IservLogin) new InitialContext(props).lookup(Constants.LOGIN_BEAN_NAME);
                groups = lb.getGroups(principal);
            } catch (NamingException ex) {
                Logger.getLogger(IservLoginModule.class.getName()).log(Level.SEVERE, null, ex);
                throw new LoginException();
            }
        }
        if (groups == null) {
            groups = new String[0];
        }
        if (groups.length == 0 && !authenticateUnknownTrustedPrincipals) {
//            Logger.getLogger(IservLoginModule.class.getName()).log(Level.INFO, "No groups.");
            throw new LoginException("No known signee.");
        }
        String[] groups2 = Arrays.copyOf(groups, groups.length + 1);
        groups2[groups2.length - 1] = "unitadmins";
//        Logger.getLogger(IservLoginModule.class.getName()).log(Level.INFO, "Groups: " + groups2.length);
        commitUserAuthentication(groups2);
    }
}
