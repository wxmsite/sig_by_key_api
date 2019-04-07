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

  void set_group()
  {
    MasterPublicKey mpk;
    relicxx::G2 msk;
    setup(mpk, msk);
    //发送一个mpk区块
  }
  set_group_return groupSetup(const set_group_args &args)
  {
    //判断群组是否存在等业务逻辑
    //如果存在,获取msk
    relicxx::G2 msk(getMsk());
    GroupSecretKey gsk);
    MasterPublicKey mpk(getMpk());
    groupSetup(args.groupID, msk, gsk, mpk);
    //返回gsk给group manager,先假设只返回给一个人
    get_sig_return final;
    final.flag = true;
    return final;
  }
  join_group_return join(const join_group_args &args)
  {
    get_sig_return final;
    return final;
  }
  // 返回用户签名
  get_sig_return get_sig(const get_sig_args &args) const
  {
    get_sig_return final;
    UserSecretKey usk;
    usk.b0 = G2(args.b0);
    usk.b3 = G2(args.b3);
    usk.b4 = G2(args.b4);
    usk.b5 = G1(args.b5);
    Sig sig;
    MasterPublicKey mpk;
    getMpk();
    sign(args.m, usk, sig, mpk);

    final.c0 = g2ToStr(sig.c0);
    final.c5 = g1ToStr(sig.c5);
    final.c6 = g2ToStr(sig.c6);
    final.e1 = g1ToStr(sig.e1);
    final.e2 = g2ToStr(sig.e2);
    final.e3 = gtToStr(sig.e3);

    final.x = zrToStr(sig.x);
    final.y = zrToStr(sig.y);
    final.z = zrToStr(sig.z);
    return final;
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
  void groupSetup(const std::string &groupID, const G2 &msk, GroupSecretKey &gsk, const MasterPublicKey &mpk)
  {
    const ZR e = group.hashListToZR(groupID);
    const ZR r1 = group.randomZR();
    gsk.a0 = group.exp(group.mul(mpk.hG2.at(0), group.exp(mpk.hG2.at(1), e)), r1);
    gsk.a0 = group.mul(msk, gsk.a0);
    gsk.a2 = group.exp(mpk.hG2.at(2), r1);
    gsk.a3 = group.exp(mpk.hG2.at(3), r1);
    ;
    gsk.a4 = group.exp(mpk.hG2.at(4), r1);
    gsk.a5 = group.exp(mpk.g, r1);
  }
  void join(const string &groupID, const string &userID, const GroupSecretKey &gsk, UserSecretKey &usk, const MasterPublicKey &mpk)
  {

    const ZR gUserID = group.hashListToZR(userID);
    const ZR gGroupID = group.hashListToZR(groupID);
    const ZR r2 = group.randomZR();

    relicxx::G2 res = group.mul(mpk.hG2.at(0), group.exp(mpk.hG2.at(1), gGroupID));
    res = group.exp(group.mul(res, group.exp(mpk.hG2.at(2), gUserID)), r2);
    usk.b0 = group.mul(gsk.a0, group.exp(gsk.a2, gUserID));
    usk.b0 = group.mul(usk.b0, res);
    usk.b3 = group.mul(gsk.a3, group.exp(mpk.hG2.at(3), r2));
    usk.b4 = group.mul(gsk.a4, group.exp(mpk.hG2.at(4), r2));
    usk.b5 = group.mul(gsk.a5, group.exp(mpk.g, r2));
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
  bool verify(const ZR &m, const Sig &sig, const string &groupID, const MasterPublicKey &mpk)
  {
    const ZR gGroupID = group.hashListToZR(getGroupID());
    const ZR y = sig.y;
    const ZR t = group.randomZR();
    const GT M = group.randomGT();
    const ZR k = sig.z;
    relicxx::G1 d1 = group.exp(mpk.g, t);
    relicxx::G2 d2 = group.mul(mpk.hG2.at(0), group.exp(mpk.hG2.at(1), gGroupID));
    d2 = group.exp(group.mul(d2, group.mul(group.exp(mpk.hG2.at(3), m), sig.c6)), t);
    relicxx::GT delta3 = group.mul(M, group.exp(group.pair(mpk.hibeg1, mpk.g2), t));
    relicxx::GT result = group.mul(delta3, group.div(group.pair(sig.c5, d2), group.pair(d1, sig.c0)));

    return M == result &&
           sig.c6 == group.mul(group.exp(mpk.hG2.at(2), sig.x), group.exp(mpk.hG2.at(4), y)) &&
           sig.e1 == group.exp(mpk.g, k) &&
           sig.e2 == group.exp(group.mul(mpk.hG2.at(0), group.exp(mpk.hG2.at(1), gGroupID)), k) &&
           sig.e3 == group.mul(group.exp(mpk.n, sig.x), group.exp(group.pair(mpk.hibeg1, mpk.g2), k));
  }

  ZR open(const MasterPublicKey &mpk, const GroupSecretKey &gsk, const Sig &sig)
  {
    const ZR gUserID = group.hashListToZR(getUserID());
    relicxx::GT t = group.exp(group.pair(mpk.hibeg1, mpk.g2), sig.z);
    //goes through all user identifiers here
    if (sig.e3 == group.mul(group.exp(mpk.n, gUserID), t))
      return gUserID;
    else
      return group.randomZR();
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
  relicxx::G2 getMsk()
  {
    return group.randomG2();
  }
  relicxx::G2 getGsk()
  {
    return group.randomG2();
  }
  string g1ToStr(relicxx::G1 g)
  {
    relicxx::GT g2;
    relicxx::G1 g;
    int len = 4 * FP_BYTES + 1;
    uint8_t bin[len];
    int l;
    l = g1_size_bin(g.g, 1);
    g1_write_bin(bin, l, g.g, 1);
    cout << "g:" << g;

    g1_read_bin(g2.g, bin, l);
    cout << "g1:" << g2;
    if (g1_cmp(g.g, g2.g) == CMP_EQ)
      cout << "eq" << endl;

    //bin to str
    string str = "";

    for (int i = 0; i < len; i++)
    {
      int m = atoi(to_string((unsigned int)bin[i]).c_str());
      const char *a = inttohex(m);
      str += a;
    }
    for (int i = str.length() / 2; i < len; i++)
      cout << (unsigned int)bin[i];
    cout << endl;
    cout << str << endl;
    cout << str.length() << " " << len << endl;
    return str;
  }
  string g2ToStr(relicxx::G2 g)
  {
    relicxx::GT g2;
    int len = 4 * FP_BYTES + 1;
    uint8_t bin[len];
    int l;
    l = g2_size_bin(g.g, 1);
    g2_write_bin(bin, l, g.g, 1);
    cout << "g:" << g;

    g2_read_bin(g2.g, bin, l);
    cout << "g2:" << g2;
    if (g2_cmp(g.g, g2.g) == CMP_EQ)
      cout << "eq" << endl;

    //bin to str
    string str = "";

    for (int i = 0; i < len; i++)
    {
      int m = atoi(to_string((unsigned int)bin[i]).c_str());
      const char *a = inttohex(m);
      str += a;
    }
    for (int i = str.length() / 2; i < len; i++)
      cout << (unsigned int)bin[i];
    cout << endl;
    cout << str << endl;
    cout << str.length() << " " << len << endl;
    return str;
  }
  string gtToStr(relicxx::GT g)
  {
    relicxx::GT g2;
    int len = 4 * FP_BYTES + 1;
    uint8_t bin[len];
    int l;
    l = g2_size_bin(g.g, 1);
    gt_write_bin(bin, l, g.g, 1);
    cout << "g:" << g;

    gt_read_bin(g2.g, bin, l);
    cout << "g2:" << g2;
    if (gt_cmp(g.g, g2.g) == CMP_EQ)
      cout << "eq" << endl;

    //bin to str
    string str = "";

    for (int i = 0; i < len; i++)
    {
      int m = atoi(to_string((unsigned int)bin[i]).c_str());
      const char *a = inttohex(m);
      str += a;
    }
    for (int i = str.length() / 2; i < len; i++)
      cout << (unsigned int)bin[i];
    cout << endl;
    cout << str << endl;
    cout << str.length() << " " << len << endl;
    return str;
  }
  string zrToStr(relicxx::ZR zr)
  {
    int len = CEIL(RELIC_BN_BITS, 8);
    bn_write_bin(bin, len, zr.z);
    for (int i = 0; i < len; i++)
      cout << bin[i];
    cout << endl;
    //bin to str
    string str = "";
    for (int i = 96; i < len; i++)
    {
      int m = atoi(to_string((unsigned int)bin[i]).c_str());
      const char *a = inttohex(m);
      str += a;
    }
    cout << endl;
    cout << str << endl;
    cout << str.length() << " " << len << endl;
  }
  relicxx::ZR strToZR(string str)
  {
    relicxx::ZR zr;
    uint8_t bin2[len];
    for (int i = 0; i < 96; i++)
      bin2[i] = '\0';
    for (int i = 0; i < str.length(); i += 2)
    {
      std::string pair = str.substr(i, 2);
      cout << pair;
      bin2[i / 2 + 96] = ::strtol(pair.c_str(), 0, 16);
    }
    cout << endl;
    bn_read_bin(zr.z, bin2, len);
    return zr;
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
