/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */
namespace osquery {

Status verifySignature(std::string b64Pub, std::string b64Sig, std::string message);

Status verifyStrictSignature(std::string b64Sig, std::string message);

Status verifyQuerySignature(std::string b64Sig, std::string query);

bool doesQueryRequireSignature(std::string query);
}