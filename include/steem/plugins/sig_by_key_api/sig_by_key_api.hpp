#pragma once
#include <steem/plugins/json_rpc/utility.hpp>
#include <steem/protocol/types.hpp>
#include <fc/optional.hpp>
#include <fc/variant.hpp>
#include <fc/vector.hpp>
#include "relic_api.hpp"
namespace steem
{
namespace plugins
{
namespace sig_by_key
{

namespace detail
{
class sig_by_key_api_impl;
}

// get_sig方法的输入参数
struct get_sig_args
{
  /* relicxx::ZR m;
  relicxx::G2 b0;
  relicxx::G2 b3;
  relicxx::G2 b4;
  relicxx::G1 b5; */
  string m;
  string b0;
  string b3;
  string b4;
  string b5;
};

// get_sig方法的输出参数
struct get_sig_return
{
  // Sig sig;
  string c0;
  string c5;
  string c6;
  string e1;
  string e2;
  string e3;
  string x;
  string y;
  string z;
};

class sig_by_key_api
{
public:
  sig_by_key_api();
  ~sig_by_key_api();

  DECLARE_API((get_sig))

private:
  std::unique_ptr<detail::sig_by_key_api_impl> my;
};
} // namespace sig_by_key
} // namespace plugins
} // namespace steem

// 将方法输入、输出参数进行反射
FC_REFLECT(steem::plugins::sig_by_key::get_sig_args, (m)(b0)(b3)(b4)(b5))
FC_REFLECT(steem::plugins::sig_by_key::get_sig_return, (c0)(c5)(c6)(e1)(e2)(e3)(x)(y)(z))