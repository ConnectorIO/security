/*
 * Copyright (C) 2019-2021 ConnectorIO Sp. z o.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package org.connectorio.security.cookie.internal;

import javax.servlet.http.Cookie;
import org.connectorio.security.CredentialValidator;
import org.openhab.core.auth.ManagedUser;
import org.openhab.core.auth.UserRegistry;
import org.openhab.core.auth.UserSession;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;

@Component(property = "result=javax.servlet.http.Cookie")
public class UserSessionCookieValidator extends UserSessionCookieValidatorBase<Cookie> implements CredentialValidator<Cookie> {

  @Activate
  public UserSessionCookieValidator(@Reference UserRegistry userRegistry) {
    super(userRegistry);
  }

  @Override
  protected boolean test(String cookieSessionId, UserSession session, ManagedUser user) {
    return cookieSessionId != null && session.hasSessionCookie() && cookieSessionId.equals(session.getSessionId());
  }

}
