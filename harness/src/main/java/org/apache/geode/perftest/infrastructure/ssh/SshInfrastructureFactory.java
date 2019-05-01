/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.geode.perftest.infrastructure.ssh;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.apache.geode.perftest.infrastructure.Infrastructure;
import org.apache.geode.perftest.infrastructure.InfrastructureFactory;

public class SshInfrastructureFactory implements InfrastructureFactory {

  private final List<String> hosts;
  private final String user;

  public SshInfrastructureFactory(String user, String... hosts) {
    List<String> tempHosts = Arrays.asList(hosts);
    String clientLocation = hosts[hosts.length-1];
    for(int i=1; i<32; i++) {
      tempHosts.add(clientLocation);
    }
    this.hosts = tempHosts;
    this.user = user;
  }

  @Override
  public Infrastructure create(int nodes) {
    if (nodes > hosts.size()) {
      throw new IllegalStateException(
          "Not enough hosts to create " + nodes + " nodes. Available hosts: " + hosts);
    }
    return new SshInfrastructure(hosts.subList(0, nodes), user);
  }

  public Collection<String> getHosts() {
    return hosts;
  }

  public String getUser() {
    return user;
  }
}
