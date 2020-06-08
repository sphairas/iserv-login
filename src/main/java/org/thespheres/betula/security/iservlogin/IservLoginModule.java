/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.thespheres.betula.security.iservlogin;

import com.sun.appserv.security.AppservPasswordLoginModule;
import com.sun.enterprise.security.auth.realm.BadRealmException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.security.auth.login.LoginException;
import org.apache.commons.net.imap.AuthenticatingIMAPClient;
import org.apache.commons.net.imap.IMAPSClient;

/**
 *
 * @author boris.heithecker
 */
public class IservLoginModule extends AppservPasswordLoginModule {
    
    @Override
    protected void authenticateUser() throws LoginException {
        String[] grpList = authorize();
        if (grpList == null || grpList.length == 0) {
            throw new LoginException();
        }
        
        boolean success = false;
        AuthenticatingIMAPClient cl;
        try {
            cl = new AuthenticatingIMAPClient(IMAPSClient.DEFAULT_PROTOCOL, true, getIservRealm().getSSLContext());
            cl.setEndpointCheckingEnabled(getIservRealm().isEndpointChecking());
            cl.connect(getIservRealm().getIservImapHost(), getIservRealm().getIservImapPort());
        } catch (IOException ex) {
            Logger.getLogger(IservLoginModule.class.getCanonicalName()).log(Level.WARNING, "Could not establish connection to iserv.", ex);
            throw new LoginException();
        } catch (BadRealmException ex) {
            throw new IllegalStateException(ex);
        }
        
        try {
            success = cl.authenticate(AuthenticatingIMAPClient.AUTH_METHOD.PLAIN, this._username, new String(this._passwd));
            cl.logout();
        } catch (IOException ex) {
            Logger.getLogger(IservLoginModule.class.getCanonicalName()).log(Level.WARNING, "Failed to log in on iserv.", ex);
            final LoginException lex = new LoginException();
            lex.initCause(ex);
            throw lex;
        } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidKeySpecException ex) {
            Logger.getLogger(IservLoginModule.class.getName()).log(Level.SEVERE, null, ex);
            final LoginException lex = new LoginException();
            lex.initCause(ex);
            throw lex;
        } finally {
            try {
                cl.disconnect();
            } catch (IOException ex) {
            }
        }
        if (success) {
            commitUserAuthentication(grpList);
        }
    }
    
    private String[] authorize() throws LoginException {
        try {
            final Properties props = new Properties();
            getIservRealm().addProperties(props);
            final IservLogin lb = (IservLogin) new InitialContext(props).lookup(Constants.LOGIN_BEAN_NAME);
            final String sfx = getIservRealm().getSigneeSuffix();
            final String suffix = sfx != null ? sfx : getIservRealm().getIservImapHost();
            return lb.getGroups(this._username, suffix);
        } catch (final NamingException ex) {
            Logger.getLogger(IservLoginModule.class.getName()).log(Level.SEVERE, null, ex);
            final LoginException lex = new LoginException();
            lex.initCause(ex);
            throw lex;
        }
    }
    
    private IservRealm getIservRealm() throws LoginException {
        try {
            return (IservRealm) getCurrentRealm();
        } catch (final ClassCastException e) {
            throw new LoginException();
        }
    }
}
