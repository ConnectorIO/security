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
package org.connectorio.security.core.internal;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.connectorio.security.AccessCredentialExtractor;
import org.connectorio.security.CredentialValidator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class DynamicSecurityRegistryTest {

  DynamicSecurityRegistry registry = new DynamicSecurityRegistry();

  @Mock
  public AccessCredentialExtractor<?, ?> simulatedExtractor;
  @Mock
  public CredentialValidator<?> validator1;
  @Mock
  public CredentialValidator<?> validator2;
  @Mock
  public CredentialValidator<?> validator3;

  @Test
  void checkExtractorRegistrationAndLookupLogic() {
    Map<String, Object> props = new HashMap<>();
    props.put("context", Http.class.getName());
    props.put("result", Cookie.class.getName());

    Optional<AccessCredentialExtractor<Http, Cookie>> extractor = registry.extractor(Http.class, Cookie.class);

    assertThat(extractor).isEmpty();
    registry.addExtractor(this.simulatedExtractor, props);

    extractor = registry.extractor(Http.class, Cookie.class);
    assertThat(extractor).isNotEmpty();
  }

  @Test
  void checkValidatorRegistrationAndLookupLogic() {
    Map<String, Object> props = new HashMap<>();
    props.put("result", Cookie.class.getName());

    assertSize(0);
    registry.addValidator(validator1, props);
    assertSize(1);

    registry.addValidator(validator2, props);
    assertSize(2);

    registry.removeValidator(validator1, props);
    assertSize(1);

    registry.removeValidator(validator2, props);
    assertSize(0);
  }

  private void assertSize(int size) {
    Set<CredentialValidator<Cookie>> validators;
    validators = registry.validators(Cookie.class);
    assertThat(validators).hasSize(size);
  }

  class Http {}
  class Cookie {}
}