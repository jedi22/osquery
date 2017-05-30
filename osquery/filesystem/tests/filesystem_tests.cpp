/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#ifndef WIN32
#include <pwd.h>
#endif

#include <algorithm>
#include <fstream>

#include <stdio.h>

#include <gtest/gtest.h>

#include <boost/filesystem.hpp>
#include <boost/property_tree/ptree.hpp>

#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/system.h>

#include "osquery/core/process.h"
#include "osquery/tests/test_util.h"

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

namespace osquery {

DECLARE_uint64(read_max);

class FilesystemTests : public testing::Test {
 protected:
  void SetUp() override {
    createMockFileStructure();

    if (isPlatform(PlatformType::TYPE_WINDOWS)) {
      etc_hosts_path_ = "C:\\Windows\\System32\\drivers\\etc\\hosts";
      etc_path_ = "C:\\Windows\\System32\\drivers\\etc";
      tmp_path_ = fs::temp_directory_path().string();
      line_ending_ = "\r\n";

      auto raw_drive = getEnvVar("SystemDrive");
      system_root_ = (raw_drive.is_initialized() ? *raw_drive : "") + "\\";
    } else {
      etc_hosts_path_ = "/etc/hosts";
      etc_path_ = "/etc";
      tmp_path_ = "/tmp";
      line_ending_ = "\n";

      system_root_ = "/";
    }
  }

  void TearDown() override {
    tearDownMockFileStructure();
  }

  /// Helper method to check if a path was included in results.
  bool contains(const std::vector<std::string>& all, const std::string& n) {
    return !(std::find(all.begin(), all.end(), n) == all.end());
  }

 protected:
  std::string etc_hosts_path_;
  std::string etc_path_;
  std::string tmp_path_;
  std::string system_root_;
  std::string line_ending_;
};

TEST_F(FilesystemTests, test_read_file) {
  std::ofstream test_file(kTestWorkingDirectory + "fstests-file");
  test_file.write("test123\n", sizeof("test123"));
  test_file.close();

  std::string content;
  auto s = readFile(kTestWorkingDirectory + "fstests-file", content);

  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  EXPECT_EQ(content, "test123" + line_ending_);

  osquery::remove(kTestWorkingDirectory + "fstests-file");
}

TEST_F(FilesystemTests, test_write_file) {
  fs::path test_file(kTestWorkingDirectory + "fstests-file2");
  std::string content(2048, 'A');

  EXPECT_TRUE(writeTextFile(test_file, content).ok());
  ASSERT_TRUE(pathExists(test_file).ok());
  ASSERT_TRUE(isWritable(test_file).ok());
  ASSERT_TRUE(osquery::remove(test_file).ok());

  EXPECT_TRUE(writeTextFile(test_file, content, (int)0400, true));
  ASSERT_TRUE(pathExists(test_file).ok());
  ASSERT_TRUE(isReadable(test_file).ok());
  {
#ifndef WIN32
    auto dropper = DropPrivileges::get();
    if (getuid() == 0) {
      auto nobody = getpwnam("nobody");
      EXPECT_TRUE(dropper->dropTo(nobody->pw_uid, nobody->pw_gid));
      EXPECT_EQ(getuid(), nobody->pw_uid);
    }
#endif
    ASSERT_FALSE(isWritable(test_file).ok());
  }
  ASSERT_TRUE(osquery::remove(test_file).ok());

  EXPECT_TRUE(writeTextFile(test_file, content, (int)0000, true));
  ASSERT_TRUE(pathExists(test_file).ok());
  {
#ifndef WIN32
    auto dropper = DropPrivileges::get();
    if (getuid() == 0) {
      auto nobody = getpwnam("nobody");
      EXPECT_TRUE(dropper->dropTo(nobody->pw_uid, nobody->pw_gid));
      EXPECT_EQ(getuid(), nobody->pw_uid);
    }
#endif
    ASSERT_FALSE(isReadable(test_file).ok());
    ASSERT_FALSE(isWritable(test_file).ok());
  }
  ASSERT_TRUE(osquery::remove(test_file).ok());
}

TEST_F(FilesystemTests, test_readwrite_file) {
  fs::path test_file(kTestWorkingDirectory + "fstests-file2");
  size_t filesize = 4096 * 10;

  std::string in_content(filesize, 'A');
  EXPECT_TRUE(writeTextFile(test_file, in_content).ok());
  ASSERT_TRUE(pathExists(test_file).ok());
  ASSERT_TRUE(isReadable(test_file).ok());

  // Now read the content back.
  std::string out_content;
  EXPECT_TRUE(readFile(test_file, out_content).ok());
  EXPECT_EQ(filesize, out_content.size());
  EXPECT_EQ(in_content, out_content);
  osquery::remove(test_file);

  // Now try to write outside of a 4k chunk size.
  in_content = std::string(filesize + 1, 'A');
  writeTextFile(test_file, in_content);
  out_content.clear();
  readFile(test_file, out_content);
  EXPECT_EQ(in_content, out_content);
  osquery::remove(test_file);
}

TEST_F(FilesystemTests, test_read_limit) {
  auto max = FLAGS_read_max;
  FLAGS_read_max = 3;
  std::string content;
  auto status = readFile(kFakeDirectory + "/root.txt", content);
  EXPECT_FALSE(status.ok());
  FLAGS_read_max = max;

  // Make sure non-link files are still readable.
  content.erase();
  status = readFile(kFakeDirectory + "/root.txt", content);
  EXPECT_TRUE(status.ok());

  // Any the links are readable too.
  status = readFile(kFakeDirectory + "/root2.txt", content);
  EXPECT_TRUE(status.ok());
}

TEST_F(FilesystemTests, test_list_files_missing_directory) {
  std::vector<std::string> results;
  auto status = listFilesInDirectory("/foo/bar", results);
  EXPECT_FALSE(status.ok());
}

TEST_F(FilesystemTests, test_list_files_invalid_directory) {
  std::vector<std::string> results;
  auto status = listFilesInDirectory("/etc/hosts", results);
  EXPECT_FALSE(status.ok());
}

TEST_F(FilesystemTests, test_list_files_valid_directory) {
  std::vector<std::string> results;

  auto s = listFilesInDirectory(etc_path_, results);
  // This directory may be different on OS X or Linux.

  replaceGlobWildcards(etc_hosts_path_);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  EXPECT_TRUE(contains(results, etc_hosts_path_));
}

TEST_F(FilesystemTests, test_intermediate_globbing_directories) {
  fs::path thirdLevelDir =
      fs::path(kFakeDirectory) / "toplevel" / "%" / "thirdlevel1";
  std::vector<std::string> results;
  resolveFilePattern(thirdLevelDir, results);
  EXPECT_EQ(results.size(), 1U);
}

TEST_F(FilesystemTests, test_canonicalization) {
  std::string complex =
      (fs::path(kFakeDirectory) / "deep1" / ".." / "deep1" / "..")
          .make_preferred()
          .string();
  std::string simple =
      (fs::path(kFakeDirectory + "/")).make_preferred().string();

  // Use the inline wildcard and canonicalization replacement.
  // The 'simple' path contains a trailing '/', the replacement method will
  // distinguish between file and directory paths.
  replaceGlobWildcards(complex);
  EXPECT_EQ(simple, complex);

  // Now apply the same inline replacement on the simple directory and expect
  // no change to the comparison.
  replaceGlobWildcards(simple);
  EXPECT_EQ(simple, complex);

  // Now add a wildcard within the complex pattern. The replacement method
  // will not canonicalize past a '*' as the proceeding paths are limiters.
  complex = (fs::path(kFakeDirectory) / "*" / "deep2" / ".." / "deep2/")
                .make_preferred()
                .string();
  replaceGlobWildcards(complex);
  EXPECT_EQ(complex,
            (fs::path(kFakeDirectory) / "*" / "deep2" / ".." / "deep2/")
                .make_preferred()
                .string());
}

TEST_F(FilesystemTests, test_simple_globs) {
  std::vector<std::string> results;

  // Test the shell '*', we will support SQL's '%' too.
  auto status = resolveFilePattern(kFakeDirectory + "/*", results);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(results.size(), 7U);

  // Test the csh-style bracket syntax: {}.
  results.clear();
  resolveFilePattern(kFakeDirectory + "/{root,door}*", results);
  EXPECT_EQ(results.size(), 3U);

  // Test a tilde, home directory expansion, make no asserts about contents.
  results.clear();
  resolveFilePattern("~", results);
  if (results.size() == 0U) {
    LOG(WARNING) << "Tilde expansion failed";
  }
}

TEST_F(FilesystemTests, test_wildcard_single_all) {
  // Use '%' as a wild card to glob files within the temporarily-created dir.
  std::vector<std::string> results;
  auto status = resolveFilePattern(kFakeDirectory + "/%", results, GLOB_ALL);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(results.size(), 7U);
  EXPECT_TRUE(contains(
      results,
      fs::path(kFakeDirectory + "/roto.txt").make_preferred().string()));
  EXPECT_TRUE(contains(
      results,
      fs::path(kFakeDirectory + "/deep11/").make_preferred().string()));
}

TEST_F(FilesystemTests, test_wildcard_single_files) {
  // Now list again with a restriction to only files.
  std::vector<std::string> results;
  resolveFilePattern(kFakeDirectory + "/%", results, GLOB_FILES);
  EXPECT_EQ(results.size(), 4U);
  EXPECT_TRUE(contains(
      results,
      fs::path(kFakeDirectory + "/roto.txt").make_preferred().string()));
}

TEST_F(FilesystemTests, test_wildcard_single_folders) {
  std::vector<std::string> results;
  resolveFilePattern(kFakeDirectory + "/%", results, GLOB_FOLDERS);
  EXPECT_EQ(results.size(), 3U);
  EXPECT_TRUE(contains(
      results,
      fs::path(kFakeDirectory + "/deep11/").make_preferred().string()));
}

TEST_F(FilesystemTests, test_wildcard_dual) {
  // Now test two directories deep with a single wildcard for each.
  std::vector<std::string> results;
  auto status = resolveFilePattern(kFakeDirectory + "/%/%", results);
  EXPECT_TRUE(status.ok());
  EXPECT_TRUE(contains(results,
                       fs::path(kFakeDirectory + "/deep1/level1.txt")
                           .make_preferred()
                           .string()));
}

TEST_F(FilesystemTests, test_wildcard_double) {
  // TODO: this will fail.
  std::vector<std::string> results;
  auto status = resolveFilePattern(kFakeDirectory + "/%%", results);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(results.size(), 20U);
  EXPECT_TRUE(contains(results,
                       fs::path(kFakeDirectory + "/deep1/deep2/level2.txt")
                           .make_preferred()
                           .string()));
}

TEST_F(FilesystemTests, test_wildcard_double_folders) {
  std::vector<std::string> results;
  resolveFilePattern(kFakeDirectory + "/%%", results, GLOB_FOLDERS);
  EXPECT_EQ(results.size(), 10U);
  EXPECT_TRUE(contains(results,
                       fs::path(kFakeDirectory + "/deep11/deep2/deep3/")
                           .make_preferred()
                           .string()));
}

TEST_F(FilesystemTests, test_wildcard_end_last_component) {
  std::vector<std::string> results;
  auto status = resolveFilePattern(kFakeDirectory + "/%11/%sh", results);
  EXPECT_TRUE(status.ok());
  EXPECT_TRUE(contains(
      results,
      fs::path(kFakeDirectory + "/deep11/not_bash").make_preferred().string()));
}

TEST_F(FilesystemTests, test_wildcard_middle_component) {
  std::vector<std::string> results;

  auto status = resolveFilePattern(kFakeDirectory + "/deep1%/%", results);

  EXPECT_TRUE(status.ok());
  EXPECT_EQ(results.size(), 5U);
  EXPECT_TRUE(contains(results,
                       fs::path(kFakeDirectory + "/deep1/level1.txt")
                           .make_preferred()
                           .string()));
  EXPECT_TRUE(contains(results,
                       fs::path(kFakeDirectory + "/deep11/level1.txt")
                           .make_preferred()
                           .string()));
}

TEST_F(FilesystemTests, test_wildcard_all_types) {
  std::vector<std::string> results;

  auto status = resolveFilePattern(kFakeDirectory + "/%p11/%/%%", results);
  EXPECT_TRUE(status.ok());
  EXPECT_TRUE(
      contains(results,
               fs::path(kFakeDirectory + "/deep11/deep2/deep3/level3.txt")
                   .make_preferred()
                   .string()));
}

TEST_F(FilesystemTests, test_wildcard_invalid_path) {
  std::vector<std::string> results;
  auto status = resolveFilePattern("/not_ther_abcdefz/%%", results);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(results.size(), 0U);
}

TEST_F(FilesystemTests, test_wildcard_dotdot_files) {
  std::vector<std::string> results;
  auto status = resolveFilePattern(
      kFakeDirectory + "/deep11/deep2/../../%", results, GLOB_FILES);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(results.size(), 4U);

  // The response list will contain canonicalized versions: /tmp/<tests>/...
  std::string door_path =
      fs::path(kFakeDirectory + "/deep11/deep2/../../door.txt")
          .make_preferred()
          .string();
  replaceGlobWildcards(door_path);
  EXPECT_TRUE(contains(results, door_path));
}

TEST_F(FilesystemTests, test_dotdot_relative) {
  std::vector<std::string> results;
  auto status = resolveFilePattern(kTestDataPath + "%", results);
  EXPECT_TRUE(status.ok());

  bool found = false;
  for (const auto& file : results) {
    if (file.find("test.config")) {
      found = true;
      break;
    }
  }
  EXPECT_TRUE(found);
}

TEST_F(FilesystemTests, test_no_wild) {
  std::vector<std::string> results;
  auto status =
      resolveFilePattern(kFakeDirectory + "/roto.txt", results, GLOB_FILES);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(results.size(), 1U);
  EXPECT_TRUE(contains(
      results,
      fs::path(kFakeDirectory + "/roto.txt").make_preferred().string()));
}

TEST_F(FilesystemTests, test_safe_permissions) {
  fs::path path_1(kFakeDirectory + "/door.txt");
  fs::path path_2(kFakeDirectory + "/deep11");

  // For testing we can request a different directory path.
  EXPECT_TRUE(safePermissions(system_root_, path_1));

  // A file with a directory.mode & 0x1000 fails.
  EXPECT_FALSE(safePermissions(tmp_path_, path_1));

  // A directory for a file will fail.
  EXPECT_FALSE(safePermissions(system_root_, path_2));

  // A root-owned file is appropriate
  if (!isPlatform(PlatformType::TYPE_WINDOWS)) {
    EXPECT_TRUE(safePermissions("/", "/dev/zero"));
  }
}

TEST_F(FilesystemTests, test_read_proc) {
  std::string content;

  if (isPlatform(PlatformType::TYPE_LINUX)) {
    fs::path stat_path("/proc/" + std::to_string(platformGetPid()) + "/stat");
    EXPECT_TRUE(readFile(stat_path, content).ok());
    EXPECT_GT(content.size(), 0U);
  }
}

TEST_F(FilesystemTests, test_read_symlink) {
  std::string content;

  if (!isPlatform(PlatformType::TYPE_WINDOWS)) {
    auto status = readFile(kFakeDirectory + "/root2.txt", content);
    EXPECT_TRUE(status.ok());
    EXPECT_EQ(content, "root");
  }
}

TEST_F(FilesystemTests, test_read_zero) {
  std::string content;

  if (!isPlatform(PlatformType::TYPE_WINDOWS)) {
    auto status = readFile("/dev/zero", content, 10);
    EXPECT_EQ(content.size(), 10U);
    for (size_t i = 0; i < 10; i++) {
      EXPECT_EQ(content[i], 0);
    }
  }
}

TEST_F(FilesystemTests, test_read_urandom) {
  std::string first, second;

  if (!isPlatform(PlatformType::TYPE_WINDOWS)) {
    auto status = readFile("/dev/urandom", first, 10);
    EXPECT_TRUE(status.ok());
    status = readFile("/dev/urandom", second, 10);
    EXPECT_NE(first, second);
  }
}
}
