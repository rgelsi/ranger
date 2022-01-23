/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.ranger.services.prestodb.client;

import org.apache.log4j.Logger;
import org.apache.ranger.plugin.util.TimedEventUtil;

import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;

public class PrestodbConnectionManager {
  private static final Logger LOG = Logger.getLogger(PrestodbConnectionManager.class);

  protected ConcurrentMap<String, PrestodbClient> prestodbConnectionCache;
  protected ConcurrentMap<String, Boolean> repoConnectStatusMap;

  public PrestodbConnectionManager() {
    prestodbConnectionCache = new ConcurrentHashMap<>();
    repoConnectStatusMap = new ConcurrentHashMap<>();
  }

  public PrestodbClient getPrestodbConnection(final String serviceName, final String serviceType, final Map<String, String> configs) {
    PrestodbClient prestodbClient = null;

    if (serviceType != null) {
      prestodbClient = prestodbConnectionCache.get(serviceName);
      if (prestodbClient == null) {
        if (configs != null) {
          final Callable<PrestodbClient> connectPrestodb = new Callable<PrestodbClient>() {
            @Override
            public PrestodbClient call() throws Exception {
              return new PrestodbClient(serviceName, configs);
            }
          };
          try {
            prestodbClient = TimedEventUtil.timedTask(connectPrestodb, 5, TimeUnit.SECONDS);
          } catch (Exception e) {
            LOG.error("Error connecting to PrestoDB repository: " +
            serviceName + " using config: " + configs, e);
          }

          PrestodbClient oldClient = null;
          if (prestodbClient != null) {
            oldClient = prestodbConnectionCache.putIfAbsent(serviceName, prestodbClient);
          } else {
            oldClient = prestodbConnectionCache.get(serviceName);
          }

          if (oldClient != null) {
            if (prestodbClient != null) {
              prestodbClient.close();
            }
            prestodbClient = oldClient;
          }
          repoConnectStatusMap.put(serviceName, true);
        } else {
          LOG.error("Connection Config not defined for asset :"
            + serviceName, new Throwable());
        }
      } else {
        try {
          prestodbClient.getCatalogList("*", null);
        } catch (Exception e) {
          prestodbConnectionCache.remove(serviceName);
          prestodbClient.close();
          prestodbClient = getPrestodbConnection(serviceName, serviceType, configs);
        }
      }
    } else {
      LOG.error("Asset not found with name " + serviceName, new Throwable());
    }
    return prestodbClient;
  }
}
