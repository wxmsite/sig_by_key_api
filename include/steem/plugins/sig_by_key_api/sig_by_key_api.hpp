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
}
// get_sum方法的输入参数
struct get_sig_args
{
  relicxx::ZR m;
};

// get_sum方法的输出参数
struct get_sig_return
{
  int64_t sum;
};

class sig_by_key
{
public:
  sig_by_key();
  ~sig_by_key();

  DECLARE_API((get_sum))

private:
  std::unique_ptr<detail::sig_by_key_impl> my;
};
} // namespace demo
} // namespace plugins
} // namespace steem

// 将方法输入、输出参数进行反射
FC_REFLECT(steem::plugins::demo::get_sig_args, (nums))
FC_REFLECT(steem::plugins::demo::get_sig_return, (sum))