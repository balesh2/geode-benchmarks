package org.apache.geode.benchmark.security;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.io.IOUtils;
import org.apache.shiro.authz.Permission;

import org.apache.geode.management.internal.security.ResourceConstants;
import org.apache.geode.security.AuthenticationFailedException;
import org.apache.geode.security.NotAuthorizedException;
import org.apache.geode.security.ResourcePermission;

public class SecurityManager implements org.apache.geode.security.SecurityManager {
  // implementation stolen from geode security example

  public static final String SECURITY_JSON = "security-json";

  protected static final String DEFAULT_JSON_FILE_NAME = "security.json";

  private Map<String, SecurityManager.User> userNameToUser;

  @Override
  public boolean authorize(final Object principal, final ResourcePermission context) {
    if (principal == null)
      return false;

    SecurityManager.User user = this.userNameToUser.get(principal.toString());
    if (user == null)
      return false; // this user is not authorized to do anything

    // check if the user has this permission defined in the context
    for (SecurityManager.Role role : this.userNameToUser.get(user.name).roles) {
      if (role == null)
        continue;
      for (Permission permitted : role.permissions) {
        if (permitted.implies(context)) {
          return true;
        }
      }
    }

    return false;
  }

  @Override
  public void init(final Properties securityProperties) throws NotAuthorizedException {
    String jsonPropertyValue =
        securityProperties != null ? securityProperties.getProperty(SECURITY_JSON) : null;
    if (jsonPropertyValue == null) {
      jsonPropertyValue = DEFAULT_JSON_FILE_NAME;
    }

    if (!initializeFromJsonResource(jsonPropertyValue)) {
      throw new AuthenticationFailedException(
          "SecurityManager: unable to find json resource \"" + jsonPropertyValue
              + "\" as specified by [" + SECURITY_JSON + "].");
    }
  }

  @Override
  public Object authenticate(final Properties credentials) throws AuthenticationFailedException {
    String user = credentials.getProperty(ResourceConstants.USER_NAME);
    String password = credentials.getProperty(ResourceConstants.PASSWORD);

    SecurityManager.User userObj = this.userNameToUser.get(user);
    if (userObj == null) {
      throw new AuthenticationFailedException("SecurityManager: wrong username/password");
    }

    if (user != null && !userObj.password.equals(password) && !"".equals(user)) {
      throw new AuthenticationFailedException("SecurityManager: wrong username/password");
    }

    return user;
  }

  boolean initializeFromJson(final String json) {
    try {
      ObjectMapper mapper = new ObjectMapper();
      JsonNode jsonNode = mapper.readTree(json);
      this.userNameToUser = new HashMap<>();
      Map<String, SecurityManager.Role> roleMap = readRoles(jsonNode);
      readUsers(this.userNameToUser, jsonNode, roleMap);
      return true;
    } catch (IOException ex) {
      return false;
    }
  }

  public boolean initializeFromJsonResource(final String jsonResource) {
    try {
      InputStream input = ClassLoader.getSystemResourceAsStream(jsonResource);
      if (input != null) {
        initializeFromJson(readJsonFromInputStream(input));
        return true;
      }
    } catch (IOException ex) {
    }
    return false;
  }

  public SecurityManager.User getUser(final String user) {
    return this.userNameToUser.get(user);
  }

  private String readJsonFromInputStream(final InputStream input) throws IOException {
    StringWriter writer = new StringWriter();
    IOUtils.copy(input, writer, "UTF-8");
    return writer.toString();
  }

  private void readUsers(final Map<String, SecurityManager.User> rolesToUsers, final JsonNode node,
                         final Map<String, SecurityManager.Role> roleMap) {
    for (JsonNode usersNode : node.get("users")) {
      SecurityManager.User user = new SecurityManager.User();
      user.name = usersNode.get("name").asText();

      if (usersNode.has("password")) {
        user.password = usersNode.get("password").asText();
      } else {
        user.password = user.name;
      }

      for (JsonNode rolesNode : usersNode.get("roles")) {
        user.roles.add(roleMap.get(rolesNode.asText()));
      }

      rolesToUsers.put(user.name, user);
    }
  }

  private Map<String, SecurityManager.Role> readRoles(final JsonNode jsonNode) {
    if (jsonNode.get("roles") == null) {
      return Collections.EMPTY_MAP;
    }
    Map<String, SecurityManager.Role> roleMap = new HashMap<>();
    for (JsonNode rolesNode : jsonNode.get("roles")) {
      SecurityManager.Role role = new SecurityManager.Role();
      role.name = rolesNode.get("name").asText();
      String regionNames = null;
      String keys = null;

      JsonNode regionsNode = rolesNode.get("regions");
      if (regionsNode != null) {
        if (regionsNode.isArray()) {
          regionNames = StreamSupport.stream(regionsNode.spliterator(), false).map(JsonNode::asText)
              .collect(Collectors.joining(","));
        } else {
          regionNames = regionsNode.asText();
        }
      }

      for (JsonNode operationsAllowedNode : rolesNode.get("operationsAllowed")) {
        String[] parts = operationsAllowedNode.asText().split(":");
        String resourcePart = (parts.length > 0) ? parts[0] : null;
        String operationPart = (parts.length > 1) ? parts[1] : null;

        if (parts.length > 2) {
          regionNames = parts[2];
        }
        if (parts.length > 3) {
          keys = parts[3];
        }

        String regionPart = (regionNames != null) ? regionNames : "*";
        String keyPart = (keys != null) ? keys : "*";

        role.permissions.add(new ResourcePermission(ResourcePermission.Resource.valueOf(resourcePart),
            ResourcePermission.Operation.valueOf(operationPart), regionPart, keyPart));
      }

      roleMap.put(role.name, role);

      if (rolesNode.has("serverGroup")) {
        role.serverGroup = rolesNode.get("serverGroup").asText();
      }
    }

    return roleMap;
  }

  public static class Role {
    List<ResourcePermission> permissions = new ArrayList<>();

    public List<ResourcePermission> getPermissions() {
      return permissions;
    }

    public void setPermissions(final List<ResourcePermission> permissions) {
      this.permissions = permissions;
    }

    public String getName() {
      return name;
    }

    public void setName(final String name) {
      this.name = name;
    }

    public String getServerGroup() {
      return serverGroup;
    }

    public void setServerGroup(final String serverGroup) {
      this.serverGroup = serverGroup;
    }

    String name;
    String serverGroup;
  }

  public static class User {
    String name;
    Set<SecurityManager.Role> roles = new HashSet<>();

    public String getName() {
      return name;
    }

    public void setName(final String name) {
      this.name = name;
    }

    public Set<SecurityManager.Role> getRoles() {
      return roles;
    }

    public void setRoles(final Set<SecurityManager.Role> roles) {
      this.roles = roles;
    }

    public String getPassword() {
      return password;
    }

    public void setPassword(final String password) {
      this.password = password;
    }

    String password;
  }

}
