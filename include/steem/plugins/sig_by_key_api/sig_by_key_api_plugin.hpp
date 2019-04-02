// 这是插件类声明的头文件，该文件名必须与plugin.json中的plugin_project字段和该插件目录
// 中CMakeLists.txt的add_library声明的库名相同，如果3者不相同的话，在编译时，插件模板
// 生成的文件中会无法正确匹配到该头文件，从而编译错误。

#pragma once
#include <steem/plugins/json_rpc/json_rpc_plugin.hpp>
#include <appbase/application.hpp>

#define STEEM_sig_by_key_api_plugin_NAME "sig_by_key_api"

namespace steem
{
namespace plugins
{
namespace sig_by_key
{
class sig_by_key_api_plugin : public appbase::plugin<sig_by_key_api_plugin>
{
public:
  sig_by_key_api_plugin(){};
  virtual ~sig_by_key_api_plugin(){};

  // 用以声明该插件依赖哪些插件
  APPBASE_PLUGIN_REQUIRES((steem::plugins::json_rpc::json_rpc_plugin))
  // 必须拥有的一个方法name，注册时用以唯一标识该插件
  static const std::string &name()
  {
    static std::string name = STEEM_sig_by_key_api_plugin_NAME;
    return name;
  }

  virtual void set_program_options(appbase::options_description &cli, appbase::options_description &cfg) override{};

  virtual void plugin_initialize(const appbase::variables_map &options) override;
  virtual void plugin_startup() override{};
  virtual void plugin_shutdown() override{};

  std::shared_ptr<class sig_by_key_api> api;
};
} // namespace sig_by_key
} // namespace plugins
} // namespace steem