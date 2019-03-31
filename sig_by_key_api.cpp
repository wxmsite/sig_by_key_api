#include <steem/plugins/sig_by_key/sig_by_key.hpp>
#include <steem/plugins/sig_by_key/sig_by_key_plugin.hpp>

namespace steem
{
namespace plugins
{
namespace demo
{

namespace detail
{

class sig_by_key_impl
{
public:
  sig_by_key_impl() {}
  ~sig_by_key_impl() {}

  // get_sum 就是我们提供的一个API方法，将输入的数组进行求和
  get_sum_return get_sum(const get_sum_args &args) const
  {
    get_sum_return final{0};
    for (auto num : args.nums)
    {
      final.sum += num;
    }
    return final;
  }
};
} // namespace detail

sig_by_key::sig_by_key() : my(new detail::sig_by_key_impl())
{
  JSON_RPC_REGISTER_API(STEEM_sig_by_key_PLUGIN_NAME);
}

sig_by_key::~sig_by_key() {}

// 需要注意创建sig_by_key的时机，因为sig_by_key的构造函数中会调用JSON RPC插件去注册API，因此
// 需要等JSON RPC先初始化好，plugin_initialize被调用时，会先注册sig_by_key_plugin的依赖
// 模块，因此可以确保此时JSON RPC插件此时已经注册完毕。
void sig_by_key_plugin::plugin_initialize(const appbase::variables_map &options)
{
  api = std::make_shared<sig_by_key>();
}

DEFINE_LOCKLESS_APIS(sig_by_key, (get_sum))
} // namespace demo
} // namespace plugins
} // namespace steem