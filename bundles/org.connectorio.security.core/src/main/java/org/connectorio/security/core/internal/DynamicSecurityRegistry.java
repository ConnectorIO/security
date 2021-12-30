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

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.connectorio.security.AccessCredentialExtractor;
import org.connectorio.security.CredentialValidator;
import org.connectorio.security.SecurityRegistry;
import org.osgi.framework.Constants;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;

@Component
public class DynamicSecurityRegistry implements SecurityRegistry {

  private final Map<ExtractorKey, ExtractorEntry> extractors = new ConcurrentHashMap<>();
  private final Map<String, Set<CredentialValidator<Object>>> validators = new ConcurrentHashMap<>();

  @Override
  public <C, R> Optional<AccessCredentialExtractor<C, R>> extractor(Class<C> context, Class<R> result) {
    ExtractorKey extractorKey = new ExtractorKey(context.getName(), result.getName());

    return Optional.ofNullable(extractors.get(extractorKey))
      .map(entry -> entry.extractor);
  }

  @Override
  public <R> Set<CredentialValidator<R>> validators(Class<R> result) {
    Set<CredentialValidator<Object>> value = validators.get(result.getName());
    if (value == null) {
      return Collections.emptySet();
    }

    return (Set) value;
  }

  @Reference(cardinality = ReferenceCardinality.MULTIPLE, policy = ReferencePolicy.DYNAMIC)
  void addExtractor(AccessCredentialExtractor<?, ?> extractor, Map<String, Object> properties) {
    ExtractorKey key = createExtractorKey(properties);
    if (key != null) {
      int ranking = Optional.ofNullable(properties.get(Constants.SERVICE_RANKING))
        .filter(rank -> rank instanceof Integer)
        .map(rank -> (Integer) rank)
        .orElse(0);
      if (!extractors.containsKey(key) || extractors.get(key).ranking < ranking) {
        extractors.put(key, new ExtractorEntry(ranking, extractor));
      }
    }
  }

  void removeExtractor(AccessCredentialExtractor<?, ?> extractor, Map<String, Object> properties) {
    ExtractorKey key = createExtractorKey(properties);
    if (key != null) {
      ExtractorEntry entry = extractors.get(key);
      if (entry.extractor == extractor) {
        extractors.remove(key);
      }
    }
  }

  @Reference(cardinality = ReferenceCardinality.MULTIPLE, policy = ReferencePolicy.DYNAMIC)
  void addValidator(CredentialValidator<?> validator, Map<String, Object> properties) {
    Object result = properties.get("result");
    if (result instanceof String) {
      String key = (String) result;
      if (!validators.containsKey(key)) {
        validators.put(key, new LinkedHashSet<>());
      }
      validators.get(key).add((CredentialValidator<Object>) validator);
    }
  }

  void removeValidator(CredentialValidator<?> validator, Map<String, Object> properties) {
    Object result = properties.get("result");
    if (result instanceof String) {
      String key = (String) result;
      if (validators.containsKey(key)) {
        Set<CredentialValidator<Object>> validatorSet = validators.get(key);
        if (validatorSet.remove(validator) && validatorSet.isEmpty()) {
          validators.remove(key);
        }
      }
    }
  }


  private ExtractorKey createExtractorKey(Map<String, Object> properties) {
    Object context = properties.get("context");
    if (context instanceof String) {
      Object result = properties.get("result");
      if (result instanceof String) {
        return new ExtractorKey((String) context, (String) result);
      }
    }
    return null;
  }

  static class ExtractorKey {
    final String context;
    final String key;

    ExtractorKey(String context, String key) {
      this.context = context;
      this.key = key;
    }
    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (!(o instanceof ExtractorKey)) {
        return false;
      }
      ExtractorKey that = (ExtractorKey) o;
      return Objects.equals(context, that.context) && Objects.equals(key, that.key);
    }

    @Override
    public int hashCode() {
      return Objects.hash(context, key);
    }
  }

  static class ExtractorEntry {
    final int ranking;
    final AccessCredentialExtractor extractor;

    ExtractorEntry(int priority, AccessCredentialExtractor extractor) {
      this.ranking = priority;
      this.extractor = extractor;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (!(o instanceof ExtractorEntry)) {
        return false;
      }
      ExtractorEntry that = (ExtractorEntry) o;
      return ranking == that.ranking && Objects.equals(extractor, that.extractor);
    }

    @Override
    public int hashCode() {
      return Objects.hash(ranking, extractor);
    }
  }
}
