package org.apache.geode.benchmark.security;

import java.util.Properties;

import org.apache.geode.security.AuthenticationFailedException;
import org.apache.geode.security.ResourcePermission;
import org.apache.geode.security.SecurityManager;

public class SimpleSecurityManager implements SecurityManager {
  // implementation stolen from geode SimpleSecurityManager example

  @Override
  public void init(final Properties securityProps) {
    // nothing
  }

  @Override
  public Object authenticate(final Properties credentials) throws AuthenticationFailedException {
    String username = credentials.getProperty("security-username");
    String password = credentials.getProperty("security-password");
    if (username != null && username.equals(password)) {
      return username;
    }
//    throw new AuthenticationFailedException("invalid username/password");
  }

  @Override
  public boolean authorize(final Object principal, final ResourcePermission permission) {
    String[] principals = principal.toString().toLowerCase().split(",");
    for (String role : principals) {
      String permissionString = permission.toString().replace(":", "").toLowerCase();
      if (permissionString.startsWith(role))
        return true;
    }
    return false;
  }

  @Override
  public void close() {
    // nothing
  }
}
