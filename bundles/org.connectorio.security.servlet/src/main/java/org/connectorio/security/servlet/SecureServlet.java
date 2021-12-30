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
package org.connectorio.security.servlet;

import java.io.IOException;
import java.util.Optional;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.connectorio.security.AccessCredentialExtractor;
import org.connectorio.security.CredentialValidator;

public abstract class SecureServlet<R> extends HttpServlet {

  private final AccessCredentialExtractor<HttpServletRequest, R> extractor;
  private final CredentialValidator<R> validator;

  protected SecureServlet(AccessCredentialExtractor<HttpServletRequest, R> extractor, CredentialValidator<R> validator) {
    this.extractor = extractor;
    this.validator = validator;
  }

  @Override
  protected final void service(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
    Optional<R> result = extractor.extract(req, validator);
    if (result.isPresent()) {
      super.service(req, resp);
    } else {
      resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }
  }
}
