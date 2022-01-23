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
package org.apache.ranger.authorization.prestodb.authorizer;

import com.facebook.presto.common.CatalogSchemaName;
import com.facebook.presto.spi.CatalogSchemaTableName;
import com.facebook.presto.spi.SchemaTableName;
import com.facebook.presto.spi.security.AccessDeniedException;
import com.facebook.presto.spi.security.PrestoPrincipal;
import com.facebook.presto.spi.security.Privilege;
import com.facebook.presto.spi.security.SystemAccessControl;
import com.facebook.presto.spi.security.AccessControlContext;
import com.facebook.presto.spi.security.Identity;
import org.apache.commons.lang.StringUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.ranger.plugin.audit.RangerDefaultAuditHandler;
import org.apache.ranger.plugin.policyengine.RangerAccessRequestImpl;
import org.apache.ranger.plugin.policyengine.RangerAccessResourceImpl;
import org.apache.ranger.plugin.policyengine.RangerAccessResult;
import org.apache.ranger.plugin.service.RangerBasePlugin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URL;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static java.util.Locale.ENGLISH;

public class RangerSystemAccessControl
  implements SystemAccessControl {
  private static Logger LOG = LoggerFactory.getLogger(RangerSystemAccessControl.class);

  final public static String RANGER_CONFIG_KEYTAB = "ranger.keytab";
  final public static String RANGER_CONFIG_PRINCIPAL = "ranger.principal";
  final public static String RANGER_CONFIG_USE_UGI = "ranger.use_ugi";
  final public static String RANGER_CONFIG_HADOOP_CONFIG = "ranger.hadoop_config";
  final public static String RANGER_PRESTODB_DEFAULT_HADOOP_CONF = "prestodb-ranger-site.xml";
  final public static String RANGER_PRESTODB_SERVICETYPE = "prestodb";
  final public static String RANGER_PRESTODB_APPID = "prestodb";

  final private RangerBasePlugin rangerPlugin;

  private boolean useUgi = false;

  public RangerSystemAccessControl(Map<String, String> config) {
    super();

    Configuration hadoopConf = new Configuration();
    if (config.get(RANGER_CONFIG_HADOOP_CONFIG) != null) {
      URL url =  hadoopConf.getResource(config.get(RANGER_CONFIG_HADOOP_CONFIG));
      if (url == null) {
        LOG.warn("Hadoop config " + config.get(RANGER_CONFIG_HADOOP_CONFIG) + " not found");
      } else {
        hadoopConf.addResource(url);
      }
    } else {
      URL url = hadoopConf.getResource(RANGER_PRESTODB_DEFAULT_HADOOP_CONF);
      if (LOG.isDebugEnabled()) {
        LOG.debug("Trying to load Hadoop config from " + url + " (can be null)");
      }
      if (url != null) {
        hadoopConf.addResource(url);
      }
    }
    UserGroupInformation.setConfiguration(hadoopConf);

    if (config.get(RANGER_CONFIG_KEYTAB) != null && config.get(RANGER_CONFIG_PRINCIPAL) != null) {
      String keytab = config.get(RANGER_CONFIG_KEYTAB);
      String principal = config.get(RANGER_CONFIG_PRINCIPAL);

      LOG.info("Performing kerberos login with principal " + principal + " and keytab " + keytab);

      try {
        UserGroupInformation.loginUserFromKeytab(principal, keytab);
      } catch (IOException ioe) {
        LOG.error("Kerberos login failed", ioe);
        throw new RuntimeException(ioe);
      }
    }

    if (config.getOrDefault(RANGER_CONFIG_USE_UGI, "false").equalsIgnoreCase("true")) {
      useUgi = true;
    }

    rangerPlugin = new RangerBasePlugin(RANGER_PRESTODB_SERVICETYPE, RANGER_PRESTODB_APPID);
    rangerPlugin.init();
    rangerPlugin.setResultProcessor(new RangerDefaultAuditHandler());
  }


  /** FILTERING **/

  @Override
  public Set<String> filterCatalogs(Identity identity, AccessControlContext context, Set<String> catalogs) {
    LOG.debug("==> RangerSystemAccessControl.filterCatalogs("+ catalogs + ")");
    Set<String> filteredCatalogs = new HashSet<>(catalogs.size());
    for (String catalog: catalogs) {
      if (hasPermission(createResource(catalog), identity, PrestodbAccessType.SELECT)) {
        filteredCatalogs.add(catalog);
      }
    }
    return filteredCatalogs;
  }

  @Override
  public Set<String> filterSchemas(Identity identity, AccessControlContext context, String catalogName, Set<String> schemaNames) {
    LOG.debug("==> RangerSystemAccessControl.filterSchemas(" + catalogName + ")");
    Set<String> filteredSchemaNames = new HashSet<>(schemaNames.size());
    for (String schemaName: schemaNames) {
      if (hasPermission(createResource(catalogName, schemaName), identity, PrestodbAccessType.SELECT)) {
        filteredSchemaNames.add(schemaName);
      }
    }
    return filteredSchemaNames;
  }

  @Override
  public Set<SchemaTableName> filterTables(Identity identity, AccessControlContext context, String catalogName, Set<SchemaTableName> tableNames) {
    LOG.debug("==> RangerSystemAccessControl.filterTables(" + catalogName + ")");
    Set<SchemaTableName> filteredTableNames = new HashSet<>(tableNames.size());
    for (SchemaTableName tableName : tableNames) {
      RangerPrestodbResource res = createResource(catalogName, tableName.getSchemaName(), tableName.getTableName());
      if (hasPermission(res, identity, PrestodbAccessType.SELECT)) {
        filteredTableNames.add(tableName);
      }
    }
    return filteredTableNames;
  }

  /** PERMISSION CHECKS ORDERED BY SYSTEM, CATALOG, SCHEMA, TABLE, VIEW, COLUMN, QUERY **/

  /** SYSTEM **/

  @Override
  public void checkCanSetSystemSessionProperty(Identity identity, AccessControlContext context, String propertyName) {
    if (!hasPermission(createSystemPropertyResource(propertyName), identity, PrestodbAccessType.ALTER)) {
      LOG.debug("RangerSystemAccessControl.checkCanSetSystemSessionProperty denied");
      AccessDeniedException.denySetSystemSessionProperty(propertyName);
    }
  }

  @Override
  public void checkCanSetUser(Identity identity, AccessControlContext context, Optional<Principal> principal, String userName) {
    // pass as it is deprecated
  }

  /** CATALOG **/
  @Override
  public void checkCanSetCatalogSessionProperty(Identity identity, AccessControlContext context, String catalogName, String propertyName) {
    if (!hasPermission(createCatalogSessionResource(catalogName, propertyName), identity, PrestodbAccessType.ALTER)) {
      LOG.debug("RangerSystemAccessControl.checkCanSetCatalogSessionProperty(" + catalogName + ") denied");
      AccessDeniedException.denySetCatalogSessionProperty(catalogName, propertyName);
    }
  }

  @Override
  public void checkCanAccessCatalog(Identity identity, AccessControlContext context, String catalogName) {
    if (!hasPermission(createResource(catalogName), identity, PrestodbAccessType.USE)) {
      LOG.debug("RangerSystemAccessControl.checkCanAccessCatalog(" + catalogName + ") denied");
      AccessDeniedException.denyCatalogAccess(catalogName);
    }
  }

  @Override
  public void checkCanShowSchemas(Identity identity, AccessControlContext context, String catalogName) {
    if (!hasPermission(createResource(catalogName), identity, PrestodbAccessType.SHOW)) {
      LOG.debug("RangerSystemAccessControl.checkCanShowSchemas(" + catalogName + ") denied");
      AccessDeniedException.denyShowSchemas(catalogName);
    }
  }

  /** SCHEMA **/

  /**
   * Create schema is evaluated on the level of the Catalog. This means that it is assumed you have permission
   * to create a schema when you have create rights on the catalog level
   */
  @Override
  public void checkCanCreateSchema(Identity identity, AccessControlContext context, CatalogSchemaName schema) {
    if (!hasPermission(createResource(schema.getCatalogName()), identity, PrestodbAccessType.CREATE)) {
      LOG.debug("RangerSystemAccessControl.checkCanCreateSchema(" + schema.getSchemaName() + ") denied");
      AccessDeniedException.denyCreateSchema(schema.getSchemaName());
    }
  }

  /**
   * This is evaluated against the schema name as ownership information is not available
   */
  @Override
  public void checkCanDropSchema(Identity identity, AccessControlContext context, CatalogSchemaName schema) {
    if (!hasPermission(createResource(schema.getCatalogName(), schema.getSchemaName()), identity, PrestodbAccessType.DROP)) {
      LOG.debug("RangerSystemAccessControl.checkCanDropSchema(" + schema.getSchemaName() + ") denied");
      AccessDeniedException.denyDropSchema(schema.getSchemaName());
    }
  }

  /**
   * This is evaluated against the schema name as ownership information is not available
   */
  @Override
  public void checkCanRenameSchema(Identity identity, AccessControlContext context, CatalogSchemaName schema, String newSchemaName) {
    RangerPrestodbResource res = createResource(schema.getCatalogName(), schema.getSchemaName());
    if (!hasPermission(res, identity, PrestodbAccessType.ALTER)) {
      LOG.debug("RangerSystemAccessControl.checkCanRenameSchema(" + schema.getSchemaName() + ") denied");
      AccessDeniedException.denyRenameSchema(schema.getSchemaName(), newSchemaName);
    }
  }

  /** TABLE **/

  @Override
  public void checkCanShowTablesMetadata(Identity identity, AccessControlContext context, CatalogSchemaName schema) {
    if (!hasPermission(createResource(schema), identity, PrestodbAccessType.SHOW)) {
      LOG.debug("RangerSystemAccessControl.checkCanShowTablesMetadata(" + schema.toString() + ") denied");
      AccessDeniedException.denyShowTablesMetadata(schema.toString());
    }
  }

  /**
   * Create table is verified on schema level
   */
  @Override
  public void checkCanCreateTable(Identity identity, AccessControlContext context, CatalogSchemaTableName table) {
    if (!hasPermission(createResource(table.getCatalogName(), table.getSchemaTableName().getSchemaName()), identity, PrestodbAccessType.CREATE)) {
      LOG.debug("RangerSystemAccessControl.checkCanCreateTable(" + table.getSchemaTableName().getTableName() + ") denied");
      AccessDeniedException.denyCreateTable(table.getSchemaTableName().getTableName());
    }
  }

  /**
   * This is evaluated against the table name as ownership information is not available
   */
  @Override
  public void checkCanDropTable(Identity identity, AccessControlContext context, CatalogSchemaTableName table) {
    if (!hasPermission(createResource(table), identity, PrestodbAccessType.DROP)) {
      LOG.debug("RangerSystemAccessControl.checkCanDropTable(" + table.getSchemaTableName().getTableName() + ") denied");
      AccessDeniedException.denyDropTable(table.getSchemaTableName().getTableName());
    }
  }

  /**
   * This is evaluated against the table name as ownership information is not available
   */
  @Override
  public void checkCanRenameTable(Identity identity, AccessControlContext context, CatalogSchemaTableName table, CatalogSchemaTableName newTable) {
    RangerPrestodbResource res = createResource(table);
    if (!hasPermission(res, identity, PrestodbAccessType.ALTER)) {
      LOG.debug("RangerSystemAccessControl.checkCanRenameTable(" + table.getSchemaTableName().getTableName() + ") denied");
      AccessDeniedException.denyRenameTable(table.getSchemaTableName().getTableName(), newTable.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanInsertIntoTable(Identity identity, AccessControlContext context, CatalogSchemaTableName table) {
    RangerPrestodbResource res = createResource(table);
    if (!hasPermission(res, identity, PrestodbAccessType.INSERT)) {
      LOG.debug("RangerSystemAccessControl.checkCanInsertIntoTable(" + table.getSchemaTableName().getTableName() + ") denied");
      AccessDeniedException.denyInsertTable(table.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanDeleteFromTable(Identity identity, AccessControlContext context, CatalogSchemaTableName table) {
    if (!hasPermission(createResource(table), identity, PrestodbAccessType.DELETE)) {
      LOG.debug("RangerSystemAccessControl.checkCanDeleteFromTable(" + table.getSchemaTableName().getTableName() + ") denied");
      AccessDeniedException.denyDeleteTable(table.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanGrantTablePrivilege(Identity identity, AccessControlContext context, Privilege privilege, CatalogSchemaTableName table, PrestoPrincipal grantee, boolean withGrantOption) {
    if (!hasPermission(createResource(table), identity, PrestodbAccessType.GRANT)) {
      LOG.debug("RangerSystemAccessControl.checkCanGrantTablePrivilege(" + table + ") denied");
      AccessDeniedException.denyGrantTablePrivilege(privilege.toString(), table.toString());
    }
  }

  @Override
  public void checkCanRevokeTablePrivilege(Identity identity, AccessControlContext context, Privilege privilege, CatalogSchemaTableName table, PrestoPrincipal revokee, boolean grantOptionFor) {
    if (!hasPermission(createResource(table), identity, PrestodbAccessType.REVOKE)) {
      LOG.debug("RangerSystemAccessControl.checkCanRevokeTablePrivilege(" + table + ") denied");
      AccessDeniedException.denyRevokeTablePrivilege(privilege.toString(), table.toString());
    }
  }

  /**
   * Create view is verified on schema level
   */
  @Override
  public void checkCanCreateView(Identity identity, AccessControlContext context, CatalogSchemaTableName view) {
    if (!hasPermission(createResource(view.getCatalogName(), view.getSchemaTableName().getSchemaName()), identity, PrestodbAccessType.CREATE)) {
      LOG.debug("RangerSystemAccessControl.checkCanCreateView(" + view.getSchemaTableName().getTableName() + ") denied");
      AccessDeniedException.denyCreateView(view.getSchemaTableName().getTableName());
    }
  }

  /**
   * This is evaluated against the table name as ownership information is not available
   */
  @Override
  public void checkCanDropView(Identity identity, AccessControlContext context, CatalogSchemaTableName view) {
    if (!hasPermission(createResource(view), identity, PrestodbAccessType.DROP)) {
      LOG.debug("RangerSystemAccessControl.checkCanDropView(" + view.getSchemaTableName().getTableName() + ") denied");
      AccessDeniedException.denyDropView(view.getSchemaTableName().getTableName());
    }
  }

  /**
   * This check equals the check for checkCanCreateView
   */
  @Override
  public void checkCanCreateViewWithSelectFromColumns(Identity identity, AccessControlContext context, CatalogSchemaTableName table, Set<String> columns) {
    try {
      checkCanCreateView(identity, context, table);
    } catch (AccessDeniedException ade) {
      LOG.debug("RangerSystemAccessControl.checkCanCreateViewWithSelectFromColumns(" + table.getSchemaTableName().getTableName() + ") denied");
      AccessDeniedException.denyCreateViewWithSelect(table.getSchemaTableName().getTableName(), identity);
    }
  }

  /** COLUMN **/

  /**
   * This is evaluated on table level
   */
  @Override
  public void checkCanAddColumn(Identity identity, AccessControlContext context, CatalogSchemaTableName table) {
    RangerPrestodbResource res = createResource(table);
    if (!hasPermission(res, identity, PrestodbAccessType.ALTER)) {
      AccessDeniedException.denyAddColumn(table.getSchemaTableName().getTableName());
    }
  }

  /**
   * This is evaluated on table level
   */
  @Override
  public void checkCanDropColumn(Identity identity, AccessControlContext context, CatalogSchemaTableName table) {
    RangerPrestodbResource res = createResource(table);
    if (!hasPermission(res, identity, PrestodbAccessType.DROP)) {
      LOG.debug("RangerSystemAccessControl.checkCanDropColumn(" + table.getSchemaTableName().getTableName() + ") denied");
      AccessDeniedException.denyDropColumn(table.getSchemaTableName().getTableName());
    }
  }

  /**
   * This is evaluated on table level
   */
  @Override
  public void checkCanRenameColumn(Identity identity, AccessControlContext context, CatalogSchemaTableName table) {
    RangerPrestodbResource res = createResource(table);
    if (!hasPermission(res, identity, PrestodbAccessType.ALTER)) {
      LOG.debug("RangerSystemAccessControl.checkCanRenameColumn(" + table.getSchemaTableName().getTableName() + ") denied");
      AccessDeniedException.denyRenameColumn(table.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanSelectFromColumns(Identity identity, AccessControlContext context, CatalogSchemaTableName table, Set<String> columns) {
    for (RangerPrestodbResource res : createResource(table, columns)) {
      if (!hasPermission(res, identity, PrestodbAccessType.SELECT)) {
        LOG.debug("RangerSystemAccessControl.checkCanSelectFromColumns(" + table.getSchemaTableName().getTableName() + ") denied");
        AccessDeniedException.denySelectColumns(table.getSchemaTableName().getTableName(), columns);
      }
    }
  }

  /** QUERY **/

  /**
   * This is a NOOP
   */
  @Override
  public void checkQueryIntegrity(Identity identity, AccessControlContext context, String query) {
  }

  /** HELPER FUNCTIONS **/

  private RangerPrestodbAccessRequest createAccessRequest(RangerPrestodbResource resource, Identity identity, PrestodbAccessType accessType) {
	String userName = null;
	Set<String> userGroups = null;

    if (useUgi) {
      UserGroupInformation ugi = UserGroupInformation.createRemoteUser(identity.getUser());

      userName = ugi.getShortUserName();
      String[] groups = ugi != null ? ugi.getGroupNames() : null;

      if (groups != null && groups.length > 0) {
        userGroups = new HashSet<>(Arrays.asList(groups));
      }
    } else {
      userName = identity.getUser();
    }

    RangerPrestodbAccessRequest request = new RangerPrestodbAccessRequest(
      resource,
      userName,
      userGroups,
      accessType
    );

    return request;
  }

  private boolean hasPermission(RangerPrestodbResource resource, Identity identity, PrestodbAccessType accessType) {
    boolean ret = false;

    RangerPrestodbAccessRequest request = createAccessRequest(resource, identity, accessType);

    RangerAccessResult result = rangerPlugin.isAccessAllowed(request);
    if (result != null && result.getIsAllowed()) {
      ret = true;
    }

    return ret;
  }

  private static RangerPrestodbResource createCatalogSessionResource(String catalogName, String propertyName) {
    RangerPrestodbResource res = new RangerPrestodbResource();
    res.setValue(RangerPrestodbResource.KEY_CATALOG, catalogName);
    res.setValue(RangerPrestodbResource.KEY_SESSION_PROPERTY, propertyName);

    return res;
  }

  private static RangerPrestodbResource createSystemPropertyResource(String property) {
    RangerPrestodbResource res = new RangerPrestodbResource();
    res.setValue(RangerPrestodbResource.KEY_SYSTEM_PROPERTY, property);

    return res;
  }

  private static RangerPrestodbResource createResource(CatalogSchemaName catalogSchemaName) {
    return createResource(catalogSchemaName.getCatalogName(), catalogSchemaName.getSchemaName());
  }

  private static RangerPrestodbResource createResource(CatalogSchemaTableName catalogSchemaTableName) {
    return createResource(catalogSchemaTableName.getCatalogName(),
      catalogSchemaTableName.getSchemaTableName().getSchemaName(),
      catalogSchemaTableName.getSchemaTableName().getTableName());
  }

  private static RangerPrestodbResource createResource(String catalogName) {
    return new RangerPrestodbResource(catalogName, Optional.empty(), Optional.empty());
  }

  private static RangerPrestodbResource createResource(String catalogName, String schemaName) {
    return new RangerPrestodbResource(catalogName, Optional.of(schemaName), Optional.empty());
  }

  private static RangerPrestodbResource createResource(String catalogName, String schemaName, final String tableName) {
    return new RangerPrestodbResource(catalogName, Optional.of(schemaName), Optional.of(tableName));
  }

  private static RangerPrestodbResource createResource(String catalogName, String schemaName, final String tableName, final Optional<String> column) {
    return new RangerPrestodbResource(catalogName, Optional.of(schemaName), Optional.of(tableName), column);
  }

  private static List<RangerPrestodbResource> createResource(CatalogSchemaTableName table, Set<String> columns) {
    List<RangerPrestodbResource> colRequests = new ArrayList<>();

    if (columns.size() > 0) {
      for (String column : columns) {
        RangerPrestodbResource rangerPrestodbResource = createResource(table.getCatalogName(),
          table.getSchemaTableName().getSchemaName(),
          table.getSchemaTableName().getTableName(), Optional.of(column));
        colRequests.add(rangerPrestodbResource);
      }
    } else {
      colRequests.add(createResource(table.getCatalogName(),
        table.getSchemaTableName().getSchemaName(),
        table.getSchemaTableName().getTableName(), Optional.empty()));
    }
    return colRequests;
  }
}

class RangerPrestodbResource
  extends RangerAccessResourceImpl {


  public static final String KEY_CATALOG = "catalog";
  public static final String KEY_SCHEMA = "schema";
  public static final String KEY_TABLE = "table";
  public static final String KEY_COLUMN = "column";
  public static final String KEY_USER = "prestodbuser";
  public static final String KEY_SYSTEM_PROPERTY = "systemproperty";
  public static final String KEY_SESSION_PROPERTY = "sessionproperty";

  public RangerPrestodbResource() {
  }

  public RangerPrestodbResource(String catalogName, Optional<String> schema, Optional<String> table) {
    setValue(KEY_CATALOG, catalogName);
    if (schema.isPresent()) {
      setValue(KEY_SCHEMA, schema.get());
    }
    if (table.isPresent()) {
      setValue(KEY_TABLE, table.get());
    }
  }

  public RangerPrestodbResource(String catalogName, Optional<String> schema, Optional<String> table, Optional<String> column) {
    setValue(KEY_CATALOG, catalogName);
    if (schema.isPresent()) {
      setValue(KEY_SCHEMA, schema.get());
    }
    if (table.isPresent()) {
      setValue(KEY_TABLE, table.get());
    }
    if (column.isPresent()) {
      setValue(KEY_COLUMN, column.get());
    }
  }

  public String getCatalogName() {
    return (String) getValue(KEY_CATALOG);
  }

  public String getTable() {
    return (String) getValue(KEY_TABLE);
  }

  public String getCatalog() {
    return (String) getValue(KEY_CATALOG);
  }

  public String getSchema() {
    return (String) getValue(KEY_SCHEMA);
  }

  public Optional<SchemaTableName> getSchemaTable() {
    final String schema = getSchema();
    if (StringUtils.isNotEmpty(schema)) {
      return Optional.of(new SchemaTableName(schema, Optional.ofNullable(getTable()).orElse("*")));
    }
    return Optional.empty();
  }
}

class RangerPrestodbAccessRequest
  extends RangerAccessRequestImpl {
  public RangerPrestodbAccessRequest(RangerPrestodbResource resource,
                                     String user,
                                     Set<String> userGroups,
                                     PrestodbAccessType prestodbAccessType) {
    super(resource, prestodbAccessType.name().toLowerCase(ENGLISH), user, userGroups, null);
    setAccessTime(new Date());
  }
}

enum PrestodbAccessType {
  CREATE, DROP, SELECT, INSERT, DELETE, USE, ALTER, ALL, GRANT, REVOKE, SHOW;
}