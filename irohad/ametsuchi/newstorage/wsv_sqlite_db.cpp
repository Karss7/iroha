/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/newstorage/wsv_sqlite_db.hpp"
#include "ametsuchi/newstorage/sqlite_wrapper.hpp"
#include <boost/filesystem/operations.hpp>
#include "sqlite_modern_cpp.h"
//#include "logger/logger.hpp"

namespace iroha {
  namespace newstorage {

    WsvSqliteDB::WsvSqliteDB(const std::string &db_file,
                               logger::LoggerPtr log)
        : db_(SqliteWrapper::create(db_file)),
          path_(db_file),
          log_(std::move(log)) {
      createSchema();
    }

    void WsvSqliteDB::loadRoles(
        const std::function<void(const std::string& role, const std::string& permissions)>&
        callback)
    {
      *db_ << "SELECT * from role" >> callback;
    }

    void WsvSqliteDB::loadDomains(
        const std::function<
            void(const std::string& role, const std::string& domain)>&
        callback
    ) {
      *db_ << "SELECT * from domain" >> callback;
    }

    void WsvSqliteDB::loadSignatories(
        const std::function<void(const std::string& signatory, size_t count)>& callback
    ) {
      *db_ << "SELECT * from signatory" >> callback;
    }

    void WsvSqliteDB::loadPeers(
        const std::function<void(const std::string& pk, const std::string& address)>& callback
    ) {
      *db_ << "SELECT * from peer" >> callback;
    }

/*
    void WsvSqliteDB::getSignatories(
        const std::string &account_id,
        std::function<void(const std::string &)> fn) {
      *db_ << "select public_key from account_has_signatory where account_id = "
              "?"
           << account_id
          >> fn;
    }

    void WsvSqliteDB::getPeers(
        std::function<void(const std::string &, const std::string &)> fn) {
      *db_ << "select * from peer" >> fn;
    }

    void WsvSqliteDB::insertPeer(const std::string &pub_key,
                                  const std::string &address) {
      *db_ << "insert into peer values (?,?)" << pub_key << address;
    }

    void WsvSqliteDB::dropPeers() {
      *db_ << "delete from peer";
    }

    void WsvSqliteDB::dropAll() {
      // TODO mutex

      db_.reset();
      boost::filesystem::remove_all(path_);
      db_ = SqliteWrapper::create(path_);
      createSchema();
    }

    int WsvSqliteDB::getTxStatusByHash(const std::string &hash) {
      int status = -1;
      *db_ << "select status from tx_status_by_hash where hash = ?" << hash
          //>> [&status](int s) { status = s; };
          >> status;
      return status;
    }
*/
    void WsvSqliteDB::createSchema() {
      static const char *prepare_tables_sql[] = {
          "CREATE TABLE IF NOT EXISTS role (\
            role_id TEXT PRIMARY KEY,\
            permission BLOB NOT NULL)",
          "CREATE TABLE IF NOT EXISTS domain (\
            domain_id TEXT PRIMARY KEY,\
            default_role TEXT NOT NULL)",
          "CREATE TABLE IF NOT EXISTS signatory (\
            public_key TEXT PRIMARY KEY,\
            count INTEGER NOT NULL)",
          "CREATE TABLE IF NOT EXISTS peer (\
            public_key TEXT PRIMARY KEY,\
            address TEXT NOT NULL UNIQUE)",
          "CREATE TABLE IF NOT EXISTS asset (\
            asset_id TEXT PRIMARY KEY,\
            domain_id TEXT NOT NULL,\
            precision INTEGER NOT NULL)",
          "CREATE TABLE IF NOT EXISTS account (\
            account_id TEXT,\
            domain_id TEXT,\
            quorum INTEGER NOT NULL,\
            PRIMARY KEY (account_id))",
          "CREATE TABLE IF NOT EXISTS account_has_signatory (\
            account_id TEXT,\
            public_key TEXT NOT NULL,\
            PRIMARY KEY (account_id, public_key))",
          "CREATE TABLE IF NOT EXISTS account_has_asset (\
            account_id TEXT NOT NULL,\
            asset_id TEXT NOT NULL,\
            amount BLOB NOT NULL,\
            PRIMARY KEY (account_id, asset_id))",
          "CREATE TABLE IF NOT EXISTS account_has_roles (\
            account_id TEXT NOT NULL,\
            role_id TEXT NOT NULL,\
            PRIMARY KEY (account_id, role_id))",
          "CREATE TABLE IF NOT EXISTS account_has_grantable_permissions (\
            permittee_account_id TEXT NOT NULL,\
            account_id TEXT NOT NULL,\
            permission BLOB NOT NULL,\
            PRIMARY KEY (permittee_account_id, account_id))",
          "CREATE TABLE IF NOT EXISTS position_by_hash (\
            hash TEXT NOT NULL,\
            height INTEGER,\
            idx INTEGER)",
          "CREATE TABLE IF NOT EXISTS tx_status_by_hash (\
            hash TEXT NOT NULL,\
            status INTEGER)",
          "CREATE TABLE IF NOT EXISTS tx_position_by_creator (\
            creator_id TEXT,\
            height INTEGER,\
            idx INTEGER)",
          "CREATE TABLE IF NOT EXISTS position_by_account_asset (\
            account_id TEXT,\
            asset_id TEXT,\
            height INTEGER,\
            idx INTEGER)",
          "CREATE INDEX IF NOT EXISTS position_by_account_asset_index\
          ON position_by_account_asset\
          (account_id, asset_id, height, idx ASC)"};

      db_->createSchema(prepare_tables_sql);
    }

  }  // namespace newstorage
}  // namespace iroha
