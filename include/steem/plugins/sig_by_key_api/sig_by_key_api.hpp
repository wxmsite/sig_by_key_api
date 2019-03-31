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
namespace demo
{

namespace detail
{
class sig_by_key_impl;
}
struct UserSecretKey
{
  relicxx::G2 b0;
  relicxx::G2 b3;
  relicxx::G2 b4;
  relicxx::G1 b5;
} struct Sig
{
  relicxx::G2 c0;
  relicxx::G1 c5;
  relicxx::G2 c6;
  relicxx::G1 e1;
  relicxx::G2 e2;
  relicxx::GT e3;
  relicxx::ZR x;
  relicxx::ZR y;
  relicxx::ZR z;
} struct MasterPublicKey
{
  unsigned int l;
  relicxx::G1 hibeg1;
  vector<relicxx::G2> hG2;
  relicxx::GT n;
}
// get_sig方法的输入参数
struct get_sig_args
{
  relicxx::ZR m;
  relicxx::G2 b0;
  relicxx::G2 b3;
  relicxx::G2 b4;
  relicxx::G1 b5;
};

// get_sig方法的输出参数
struct get_sig_return
{
  Sig sig;
};

class sig_by_key
{
public:
  sig_by_key();
  ~sig_by_key();

  DECLARE_API((get_sig))

private:
  std::unique_ptr<detail::sig_by_key_impl> my;
};
} // namespace demo
} // namespace plugins
} // namespace steem

// 将方法输入、输出参数进行反射
FC_REFLECT(steem::plugins::demo::get_sig_args, (m)(b0)(b3)(b4)(b5))
FC_REFLECT(steem::plugins::demo::get_sig_return, (sig))