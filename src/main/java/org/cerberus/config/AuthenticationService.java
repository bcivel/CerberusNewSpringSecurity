/**
 * Cerberus Copyright (C) 2013 - 2017 cerberustesting
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This file is part of Cerberus.
 *
 * Cerberus is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Cerberus is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Cerberus.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.cerberus.config;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import org.cerberus.crud.dao.impl.UserDAO;
import org.cerberus.crud.entity.UserGroup;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 *
 * @author bcivel
 */
@Service
public class AuthenticationService implements UserDetailsService {

    @Autowired
    private UserDAO userDAO;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        org.cerberus.crud.entity.User usr = userDAO.findUserByKey(username);
        User user = new User(usr.getLogin(), usr.getPassword(), getAuthorities(usr.getUserGroups()));
        UserDetails userDetails = (UserDetails) user;
        
        return userDetails;
    }

    private Collection<? extends GrantedAuthority> getAuthorities(List<UserGroup> roles) {
        List<GrantedAuthority> authorities  = new ArrayList<>();
        for (UserGroup role : roles) {
            authorities.add(new SimpleGrantedAuthority(role.getGroup()));
        }
        return authorities;
    }
    
    
}
