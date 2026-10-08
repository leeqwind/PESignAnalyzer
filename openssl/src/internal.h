#pragma once

#include "pesign/analyzer.h"

namespace pesign::detail {

// Accepts the WIN_CERTIFICATE payload (zero alignment padding is allowed).
// Appends the outer signature and nested signatures; errors are kept in result.
void parse_pkcs7(const std::uint8_t* data, std::size_t size,
                 std::size_t certificate_record, Analysis& result,
                 const Options* chain_options = nullptr);

Analysis parse_pe_metadata(const std::vector<std::uint8_t>& bytes,
                           const Options* chain_options);

} // namespace pesign::detail
