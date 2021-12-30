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
package org.connectorio.security.validator;

import java.util.List;
import org.connectorio.security.CredentialValidator;

public class AnyValidator<R> implements CredentialValidator<R> {

  private final List<CredentialValidator<R>> validators;

  public AnyValidator(List<CredentialValidator<R>> validators) {
    this.validators = validators;
  }

  @Override
  public boolean validate(R credential) {
    for (CredentialValidator<R> validator : validators) {
      if (validator.validate(credential)) {
        return true;
      }
    }

    return false;
  }
}
