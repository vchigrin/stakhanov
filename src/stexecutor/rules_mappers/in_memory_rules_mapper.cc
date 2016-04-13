// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "stexecutor/rules_mappers/in_memory_rules_mapper.h"

#include <vector>
#include <string>

#include "log4cplus/logger.h"
#include "log4cplus/loggingmacros.h"
#include "stexecutor/rules_mappers/cached_execution_response.h"
#include "stexecutor/rules_mappers/in_memory_request_results.h"
#include "stexecutor/process_creation_request.h"
#include "boost/archive/xml_oarchive.hpp"
#include "boost/filesystem/fstream.hpp"
#include "boost/serialization/split_free.hpp"

namespace boost {
namespace serialization {

template<typename Archive>
void save(
    Archive& ar,  // NOLINT
    const boost::filesystem::path& path,
    const unsigned int) {
  ar & boost::serialization::make_nvp("path", path.generic_string());
}

template<typename Archive>
void save(
    Archive& ar,  // NOLINT
    const rules_mappers::HashValue& value,
    const unsigned int) {
  std::wstringstream strm;
  strm << value;
  ar & boost::serialization::make_nvp("hash", strm.str());
}

template<typename Archive>
void save(
    Archive& ar,  // NOLINT
    const rules_mappers::FileInfo& value,
    const unsigned int) {
  ar & boost::serialization::make_nvp(
      "rel_file_path", value.rel_file_path);
  ar & boost::serialization::make_nvp(
      "storage_content_id", value.storage_content_id);
}

}  // namespace serialization
}  // namespace boost

BOOST_SERIALIZATION_SPLIT_FREE(boost::filesystem::path)
BOOST_SERIALIZATION_SPLIT_FREE(rules_mappers::HashValue)
BOOST_SERIALIZATION_SPLIT_FREE(rules_mappers::FileInfo)

namespace {

log4cplus::Logger logger_ = log4cplus::Logger::getInstance(
    L"InMemoryRulesMapper");
}

namespace rules_mappers {

InMemoryRulesMapper::InMemoryRulesMapper() {
}

InMemoryRulesMapper::~InMemoryRulesMapper() {
}

const CachedExecutionResponse* InMemoryRulesMapper::FindCachedResults(
    const ProcessCreationRequest& process_creation_request,
    const BuildDirectoryState& build_dir_state,
    std::vector<FileInfo>* input_files) {
  HashValue request_hash = ComputeProcessCreationHash(
      process_creation_request);
  auto it = rules_.find(request_hash);
  if (it == rules_.end()) {
    LOG4CPLUS_INFO(logger_, "No rule set for hash " << request_hash);
    return nullptr;
  }
  LOG4CPLUS_INFO(logger_, "Found rule set for hash " << request_hash);
  return it->second->FindCachedResults(build_dir_state, input_files);
}

void InMemoryRulesMapper::AddRule(
    const ProcessCreationRequest& process_creation_request,
    std::vector<FileInfo> input_files,
    std::unique_ptr<CachedExecutionResponse> response) {
  HashValue request_hash = ComputeProcessCreationHash(
      process_creation_request);
  auto it = rules_.find(request_hash);
  InMemoryRequestResults* results = nullptr;
  if (it != rules_.end()) {
    LOG4CPLUS_INFO(logger_,
        "Already have rule set for hash " << request_hash);
    results = it->second.get();
  } else {
    LOG4CPLUS_INFO(logger_,
        "Creating new rule set for hash " << request_hash);
    std::unique_ptr<InMemoryRequestResults> new_results(
        new InMemoryRequestResults());
    results = new_results.get();
    rules_.insert(std::make_pair(request_hash, std::move(new_results)));
  }
  results->AddRule(std::move(input_files), std::move(response));
  if (!dbg_dump_rules_dir_.empty()) {
    DumpRequestResults(results, process_creation_request, request_hash);
  }
}

void InMemoryRulesMapper::DumpRequestResults(
    InMemoryRequestResults* results,
    const ProcessCreationRequest& process_creation_request,
    const HashValue& hash_value) {
  std::wstringstream file_name_buf;
  file_name_buf << hash_value << L".xml";
  boost::filesystem::path file_path =
      dbg_dump_rules_dir_ / file_name_buf.str();
  boost::filesystem::ofstream stream(file_path);
  boost::archive::xml_oarchive archive(stream);
  archive & BOOST_SERIALIZATION_NVP(process_creation_request);
  archive & boost::serialization::make_nvp("results", *results);
}

}  // namespace rules_mappers
