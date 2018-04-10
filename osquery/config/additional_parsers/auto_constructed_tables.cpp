/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/config.h>
#include <osquery/database.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/sql.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/sql/sqlite_util.h"

namespace rj = rapidjson;

namespace osquery {

/**
 * @brief A ConfigParserPlugin for ATC (Auto Table Construction)
 */
class ATCConfigParserPlugin : public ConfigParserPlugin {
  const std::string kParserKey = "auto_table_construction";
  const std::string kDatabaseKeyPrefix = "atc.";

  Status removeATCTables(const std::set<std::string>& tables);
  std::set<std::string> registeredATCTables();

 public:
  std::vector<std::string> keys() const override {
    return {kParserKey};
  }

  Status setUp() override;
  Status update(const std::string& source, const ParserConfig& config) override;
};

class ATCPlugin : public TablePlugin {
  TableColumns tc_columns_;
  std::string sqlite_query_;
  std::string path_;

  TableColumns columns() const override {
    return tc_columns_;
  }

 public:
  ATCPlugin(const std::string& path,
            const TableColumns& tc_columns,
            const std::string& sqlite_query) {
    path_ = path;
    sqlite_query_ = sqlite_query;
    tc_columns_ = tc_columns;
  }

  QueryData generate(QueryContext& context) override {
    QueryData qd;
    std::vector<std::string> paths;
    auto s = resolveFilePattern(path_, paths);

    for (const auto& path : paths) {
      s = genQueryDataForSqliteTable(path, sqlite_query_, qd);
      if (!s.ok()) {
        LOG(WARNING) << "Error Code: " << s.getCode()
                     << " Could not generate data: " << s.getMessage();
      }
    }
    return qd;
  }

 protected:
  std::string columnDefinition() const {
    return ::osquery::columnDefinition(tc_columns_);
  }
};

/// Remove these ATC tables from the registry and database
Status ATCConfigParserPlugin::removeATCTables(
    const std::set<std::string>& detach_tables) {
  auto registry_table = RegistryFactory::get().registry("table");
  for (const auto& table : detach_tables) {
    if (registry_table->exists(table)) {
      registry_table->remove(table);
      LOG(INFO) << "Removed ATC table: " << table;
    }
    deleteDatabaseValue(kPersistentSettings, kDatabaseKeyPrefix + table);
  }
  return Status{};
}

/// Get all ATC tables that should be registered from the database
std::set<std::string> ATCConfigParserPlugin::registeredATCTables() {
  std::vector<std::string> tables;
  scanDatabaseKeys(kPersistentSettings, tables, kDatabaseKeyPrefix);
  std::set<std::string> set_tables;

  for (const auto& table : tables) {
    set_tables.insert(table.substr(kDatabaseKeyPrefix.size()));
  }
  return set_tables;
}

Status ATCConfigParserPlugin::setUp() {
  VLOG(1) << "Removing stale ATC entries";
  std::vector<std::string> keys;
  scanDatabaseKeys(kPersistentSettings, keys, kDatabaseKeyPrefix);
  for (const auto& key : keys) {
    deleteDatabaseValue(kPersistentSettings, key);
  }
  return Status{};
}

Status ATCConfigParserPlugin::update(const std::string& source,
                                     const ParserConfig& config) {
  auto cv = config.find(kParserKey);
  if (cv == config.end()) {
    removeATCTables(registeredATCTables());
    return Status(1, "No configuration for ATC (Auto Table Construction)");
  }

  auto obj = data_.getObject();
  data_.copyFrom(cv->second.doc(), obj);
  data_.add(kParserKey, obj);

  const auto& ac_tables = data_.doc()[kParserKey];
  auto tables = RegistryFactory::get().registry("table");
  auto registered = registeredATCTables();

  for (const auto& ac_table : ac_tables.GetObject()) {
    std::string table_name{ac_table.name.GetString()};
    auto params = ac_table.value.GetObject();

    std::string query{params["query"].GetString()};
    std::string path{params["path"].GetString()};

    TableColumns columns;
    std::string columns_value;
    columns_value.reserve(256);

    for (const auto& column : params["columns"].GetArray()) {
      columns.push_back(make_tuple(
          std::string(column.GetString()), TEXT_TYPE, ColumnOptions::DEFAULT));
      columns_value += std::string(column.GetString()) + ",";
    }

    registered.erase(table_name);
    std::string table_settings{table_name + query + columns_value + path};
    std::string old_setting;
    auto s = getDatabaseValue(
        kPersistentSettings, kDatabaseKeyPrefix + table_name, old_setting);

    // The ATC table hasn't changed so we skip ahead
    if (table_settings == old_setting) {
      continue;
    }

    // Remove the old table to replace with the new one
    removeATCTables({table_name});
    setDatabaseValue(
        kPersistentSettings, kDatabaseKeyPrefix + table_name, table_settings);
    tables->add(table_name, std::make_shared<ATCPlugin>(path, columns, query));
    LOG(INFO) << "Registered ATC table: " << table_name;
  }

  if (registered.size() > 0) {
    VLOG(1)
        << "Removing any ATC tables that were removed in this configuration "
           "change";
    removeATCTables(registered);
  }
  return Status{};
}

REGISTER_INTERNAL(ATCConfigParserPlugin,
                  "config_parser",
                  "auto_constructed_tables");
} // namespace osquery
