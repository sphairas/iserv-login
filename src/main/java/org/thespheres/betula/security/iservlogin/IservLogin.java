/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.thespheres.betula.security.iservlogin;

/**
 *
 * @author boris.heithecker
 */
public interface IservLogin {

    public static final long serialVersionUID = 2L;

    public String[] getGroups(String prefix, String suffix);

}
