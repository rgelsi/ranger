/*
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
 */
package org.apache.ranger.authorization.prestodb.authorizer;

import com.facebook.presto.common.CatalogSchemaName;
import com.facebook.presto.spi.connector.CatalogSchemaTableName;
import com.facebook.presto.spi.connector.ColumnMetadata;
import com.facebook.presto.spi.connector.SchemaTableName;
import com.facebook.presto.spi.security.PrestoPrincipal;
import com.facebook.presto.spi.security.Privilege;
import com.facebook.presto.spi.security.SystemAccessControl;
import com.facebook.presto.spi.type.Type;
import org.apache.ranger.plugin.classloader.RangerPluginClassLoader;

import javax.inject.Inject;
import java.security.Principal;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

public class RangerSystemAccessControl
  implements SystemAccessControl {
  private static final String RANGER_PLUGIN_TYPE = "prestodb";
  private static final String RANGER_PRESTODB_AUTHORIZER_IMPL_CLASSNAME = "org.apache.ranger.authorization.prestodb.authorizer.RangerSystemAccessControl";

  final private RangerPluginClassLoader rangerPluginClassLoader;
  final private SystemAccessControl systemAccessControlImpl;

  @Inject
  public RangerSystemAccessControl(RangerConfig config) {
    try {
      rangerPluginClassLoader = RangerPluginClassLoader.getInstance(RANGER_PLUGIN_TYPE, this.getClass());

      @SuppressWarnings("unchecked")
      Class<SystemAccessControl> cls = (Class<SystemAccessControl>) Class.forName(RANGER_PRESTODB_AUTHORIZER_IMPL_CLASSNAME, true, rangerPluginClassLoader);

      activatePluginClassLoader();

      Map<String, String> configMap = new HashMap<>();
      if (config.getKeytab() != null && config.getPrincipal() != null) {
        configMap.put("ranger.keytab", config.getKeytab());
        configMap.put("ranger.principal", config.getPrincipal());
      }

      if (config.getHadoopConfigPath() != null) {
        configMap.put("ranger.hadoop_config", config.getHadoopConfigPath());
      }

      systemAccessControlImpl = cls.getDeclaredConstructor(Map.class).newInstance(configMap);
    } catch (Exception e) {
      throw new RuntimeException(e);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanSetSystemSessionProperty(Identity identity, String propertyName) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanSetSystemSessionProperty(identity, propertyName);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanAccessCatalog(Identity identity, String catalogName) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanAccessCatalog(identity, catalogName);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public Set<String> filterCatalogs(Identity identity, Set<String> catalogs) {
    Set<String> filteredCatalogs;
    try {
      activatePluginClassLoader();
      filteredCatalogs = systemAccessControlImpl.filterCatalogs(identity, catalogs);
    } finally {
      deactivatePluginClassLoader();
    }
    return filteredCatalogs;
  }

  @Override
  public void checkCanCreateSchema(Identity identity, CatalogSchemaName schema) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanCreateSchema(identity, schema);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanDropSchema(Identity identity, CatalogSchemaName schema) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanDropSchema(identity, schema);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanRenameSchema(Identity identity, CatalogSchemaName schema, String newSchemaName) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanRenameSchema(identity, schema, newSchemaName);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanShowSchemas(Identity identity, String catalogName) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanShowSchemas(identity, catalogName);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public Set<String> filterSchemas(Identity identity, String catalogName, Set<String> schemaNames) {
    Set<String> filteredSchemas;
    try {
      activatePluginClassLoader();
      filteredSchemas = systemAccessControlImpl.filterSchemas(identity, catalogName, schemaNames);
    } finally {
      deactivatePluginClassLoader();
    }
    return filteredSchemas;
  }

  @Override
  public void checkCanCreateTable(Identity identity, CatalogSchemaTableName table) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanCreateTable(identity, table);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanDropTable(Identity identity, CatalogSchemaTableName table) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanDropTable(identity, table);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanRenameTable(Identity identity, CatalogSchemaTableName table, CatalogSchemaTableName newTable) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanRenameTable(identity, table, newTable);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public Set<SchemaTableName> filterTables(Identity identity, String catalogName, Set<SchemaTableName> tableNames) {
    Set<SchemaTableName> filteredTableNames;
    try {
      activatePluginClassLoader();
      filteredTableNames = systemAccessControlImpl.filterTables(identity, catalogName, tableNames);
    } finally {
      deactivatePluginClassLoader();
    }
    return filteredTableNames;
  }

  @Override
  public void checkCanAddColumn(Identity identity, CatalogSchemaTableName table) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanAddColumn(identity, table);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanDropColumn(Identity identity, CatalogSchemaTableName table) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanDropColumn(identity, table);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanRenameColumn(Identity identity, CatalogSchemaTableName table) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanRenameColumn(identity, table);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanSelectFromColumns(Identity identity, CatalogSchemaTableName table, Set<String> columns) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanSelectFromColumns(identity, table, columns);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanInsertIntoTable(Identity identity, CatalogSchemaTableName table) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanInsertIntoTable(identity, table);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanDeleteFromTable(Identity identity, CatalogSchemaTableName table) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanDeleteFromTable(identity, table);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanCreateView(Identity identity, CatalogSchemaTableName view) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanCreateView(identity, view);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanDropView(Identity identity, CatalogSchemaTableName view) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanDropView(identity, view);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanCreateViewWithSelectFromColumns(Identity identity, CatalogSchemaTableName table, Set<String> columns) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanCreateViewWithSelectFromColumns(identity, table, columns);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanSetCatalogSessionProperty(Identity identity, String catalogName, String propertyName) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanSetCatalogSessionProperty(identity, catalogName, propertyName);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanImpersonateUser(Identity identity, String userName) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanImpersonateUser(identity, userName);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanExecuteQuery(Identity identity) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanExecuteQuery(identity);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanViewQueryOwnedBy(Identity identity, String queryOwner) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanViewQueryOwnedBy(identity, queryOwner);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public Set<String> filterViewQueryOwnedBy(Identity identity, Set<String> queryOwners) {
    Set<String> filteredQueryOwners;
    try {
      activatePluginClassLoader();
      filteredQueryOwners = systemAccessControlImpl.filterViewQueryOwnedBy(identity, queryOwners);
    } finally {
      deactivatePluginClassLoader();
    }
    return filteredQueryOwners;
  }

  @Override
  public void checkCanKillQueryOwnedBy(Identity identity, String queryOwner) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanKillQueryOwnedBy(identity, queryOwner);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanShowCreateTable(Identity identity, CatalogSchemaTableName table) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanShowCreateTable(identity, table);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanSetTableComment(Identity identity, CatalogSchemaTableName table) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanSetTableComment(identity, table);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanShowTables(Identity identity, CatalogSchemaName schema) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanShowTables(identity, schema);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanShowColumns(Identity identity, CatalogSchemaTableName table) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanShowColumns(identity, table);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public List<ColumnMetadata> filterColumns(Identity identity, CatalogSchemaTableName table, List<ColumnMetadata> columns) {
    List<ColumnMetadata> filteredColumns;
    try {
      activatePluginClassLoader();
      filteredColumns = systemAccessControlImpl.filterColumns(identity, table, columns);
    } finally {
      deactivatePluginClassLoader();
    }
    return filteredColumns;
  }

  @Override
  public void checkCanRenameView(Identity identity, CatalogSchemaTableName view, CatalogSchemaTableName newView) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanRenameView(identity, view, newView);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanGrantTablePrivilege(Identity identity, Privilege privilege, CatalogSchemaTableName table, PrestoPrincipal grantee, boolean withGrantOption) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanGrantTablePrivilege(identity, privilege, table, grantee, withGrantOption);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanRevokeTablePrivilege(Identity identity, Privilege privilege, CatalogSchemaTableName table, PrestoPrincipal revokee, boolean grantOptionFor) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanRevokeTablePrivilege(identity, privilege, table, revokee, grantOptionFor);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanShowRoles(Identity identity, String catalogName) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanShowRoles(identity, catalogName);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanSetUser(Optional<Principal> principal, String userName) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanSetUser(principal, userName);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanSetSchemaAuthorization(Identity identity, CatalogSchemaName schema, PrestoPrincipal principal) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanSetSchemaAuthorization(identity, schema, principal);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanShowCreateSchema(Identity identity, CatalogSchemaName schemaName) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanShowCreateSchema(identity, schemaName);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  private void activatePluginClassLoader() {
    if (rangerPluginClassLoader != null) {
      rangerPluginClassLoader.activate();
    }
  }

  private void deactivatePluginClassLoader() {
    if (rangerPluginClassLoader != null) {
      rangerPluginClassLoader.deactivate();
    }
  }
}
