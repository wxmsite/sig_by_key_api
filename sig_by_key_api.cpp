#include <steem/plugins/sig_by_key_api/sig_by_key_api.hpp>
#include <steem/plugins/sig_by_key_api/sig_by_key_api_plugin.hpp>
#include <steem/plugins/sig_by_key_api/HibeGS.hpp>

using namespace relicxx;
using namespace forwardsec;
namespace steem
{
namespace plugins
{
namespace sig_by_key
{

namespace detail
{

class sig_by_key_api_impl
{
public:
  PairingGroup group;
  sig_by_key_api_impl() {}
  ~sig_by_key_api_impl() {}

  // 返回用户签名
  get_sig_return get_sig(const get_sig_args &args) const
  {
    get_sig_return final{0};
    /*  UserSecretKey usk;
    usk.b0 = args.b0;
    usk.b3 = G2(args.b3);
    usk.b4 = args.b4;
    usk.b5 = args.b5;
    Sig sig;
    MasterPublicKey mpk;
    getMpk();
    sign(args.m, usk, sig, mpk);
    final.sig = sig; */
    final.c0="1111112222222222222222412222222";
    final.c5="1111112222222222222222412222222";
    final.c6="1111112222222222222222412222222";
    final.e1="1111112222222222222222412222222";
    final.e2="1111112222222222222222412222222";
    final.e3="1111112222222222222222412222222";
    final.x="1111112222222222222222412222222";
    final.y="1111112222222222222222412222222";
    final.z="1111112222222222222222412222222";
    return final;
  }
  void set_group()
  {
    MasterPublicKey mpk;
    relicxx::G2 msk;
    setup(mpk, msk);
    //发送一个mpk区块
  }

private:
  void setup(MasterPublicKey &mpk, relicxx::G2 &msk) const
  {
    const unsigned int l = 4;
    ZR alpha = group.randomZR();
    mpk.g = group.randomG1();
    mpk.g2 = group.randomG2();
    mpk.hibeg1 = group.exp(mpk.g, alpha);
    //we setup four level HIBE here,the first level is Group identity,the second level is user identity
    //the third level is the signed message,the last level is a random identity
    mpk.l = 4;
    for (unsigned int i = 0; i <= l; i++)
    {
      ZR h = group.randomZR();
      mpk.hG2.push_back(group.exp(mpk.g2, h));
    }
    mpk.n = group.randomGT();
    msk = group.exp(mpk.g2, alpha);
  }
  void sign(const ZR &m, const UserSecretKey &usk, Sig &sig, const MasterPublicKey &mpk)
  {
    const ZR gUserID = group.hashListToZR(getUserID());
    const ZR gGroupID = group.hashListToZR(getGroupID());
    //G(UserID),G(r4),k are public
    const ZR r3 = group.randomZR();
    //r4 use to blind identity
    const ZR r4 = group.randomZR();
    //user to encrypt identity to the group manager
    const ZR k = group.randomZR();
    relicxx::G2 res = group.mul(mpk.hG2.at(0), group.exp(mpk.hG2.at(1), gGroupID));
    res = group.mul(res, group.exp(mpk.hG2.at(2), gUserID));
    res = group.mul(res, group.exp(mpk.hG2.at(3), m));
    res = group.exp(group.mul(res, group.exp(mpk.hG2.at(4), r4)), r3);
    sig.c0 = group.mul(usk.b0, group.exp(usk.b3, m));
    sig.c0 = group.mul(group.mul(sig.c0, group.exp(usk.b4, r4)), res);
    sig.c5 = group.mul(usk.b5, group.exp(mpk.g, r3));

    sig.c6 = group.mul(group.exp(mpk.hG2.at(2), gUserID), group.exp(mpk.hG2.at(4), r4));
    sig.e1 = group.exp(mpk.g, k);
    sig.e2 = group.exp(group.mul(mpk.hG2.at(0), group.exp(mpk.hG2.at(1), gGroupID)), k);

    sig.e3 = group.exp(group.pair(mpk.g2, mpk.hibeg1), k);
    sig.e3 = group.mul(sig.e3, group.exp(mpk.n, gUserID));
    sig.x = gUserID;
    sig.y = r4;
    sig.z = k;
  }
  void getMpk(MasterPublicKey &mpk)
  {
    relicxx::G2 msk;
    setup(mpk, msk);
  }
  string getGroupID()
  {
    return "science";
  }
  //可能需要多种场景
  string getUserID()
  {
    return "www";
  }
};
} // namespace detail

sig_by_key_api::sig_by_key_api() : my(new detail::sig_by_key_api_impl())
{
  JSON_RPC_REGISTER_API(STEEM_sig_by_key_api_plugin_NAME);
}

sig_by_key_api::~sig_by_key_api() {}

// 需要注意创建sig_by_key的时机，因为sig_by_key的构造函数中会调用JSON RPC插件去注册API，因此
// 需要等JSON RPC先初始化好，plugin_initialize被调用时，会先注册sig_by_key_api_plugin的依赖
// 模块，因此可以确保此时JSON RPC插件此时已经注册完毕。
void sig_by_key_api_plugin::plugin_initialize(const appbase::variables_map &options)
{
  api = std::make_shared<sig_by_key_api>();
}

DEFINE_LOCKLESS_APIS(sig_by_key_api, (get_sig))
} // namespace sig_by_key
} // namespace plugins
} // namespace steem