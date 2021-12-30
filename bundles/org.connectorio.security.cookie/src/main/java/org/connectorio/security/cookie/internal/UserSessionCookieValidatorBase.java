package org.connectorio.security.cookie.internal;

import javax.servlet.http.Cookie;
import org.connectorio.security.CredentialValidator;
import org.openhab.core.auth.ManagedUser;
import org.openhab.core.auth.User;
import org.openhab.core.auth.UserRegistry;
import org.openhab.core.auth.UserSession;

abstract class UserSessionCookieValidatorBase<T extends Cookie> implements CredentialValidator<T> {

  private final UserRegistry userRegistry;

  public UserSessionCookieValidatorBase(UserRegistry userRegistry) {
    this.userRegistry = userRegistry;
  }

  @Override
  public boolean validate(Cookie credential) {
    for (User user : userRegistry.getAll()) {
      if (user instanceof ManagedUser) {
        for (UserSession session : ((ManagedUser) user).getSessions()) {
          if (test(credential.getValue(), session, (ManagedUser) user)) {
            return true;
          }
        }
      }
    }
    return false;
  }

  protected abstract boolean test(String cookieSessionId, UserSession session, ManagedUser user);
}
