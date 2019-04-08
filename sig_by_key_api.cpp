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
  relicResourceHandle relic;
  PairingGroup group;

  sig_by_key_api_impl() {}
  ~sig_by_key_api_impl() {}

  set_group_return set_group(const set_group_args &args) const
  {
    //判断群组是否存在等业务逻辑
    //如果存在,获取msk
    relicxx::G2 msk(getMsk());
    GroupSecretKey gsk;
    MasterPublicKey mpk(getMpk());
    groupSetup(args.groupID, msk, gsk, mpk);
    //返回gsk给group manager,先假设只返回给一个人
    set_group_return final;
    final.a0 = g2ToStr(gsk.a0);
    final.a2 = g2ToStr(gsk.a2);
    final.a3 = g2ToStr(gsk.a3);
    final.a4 = g2ToStr(gsk.a4);
    final.a5 = g1ToStr(gsk.a5);
    return final;
  }
  join_group_return join_group(const join_group_args &args) const
  {
    join_group_return final;
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
    Signature sig;
    MasterPublicKey mpk(getMpk());
    relicxx::ZR m = hashListToZR(m);

    sign(m, usk, sig, mpk);

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
  test_return test(const test_args &args)
  {
    test_return final;
    MasterPublicKey mpk;
    relicxx::G2 msk;
    setup(mpk, msk);

    const set_group_args set_args("science");
    set_group_return sgr = set_group(set_args);
    GroupSecretKey gsk;
    gsk.a0 = strToG2(sgr.a0);
    gsk.a2 = strToG2(sgr.a2);
    gsk.a3 = strToG2(sgr.a3);
    gsk.a4 = strToG2(sgr.a4);
    gsk.a5 = strToG1(sgr.a5);
    const join_group_args join_args("‘science"."www");
    join_group_return jgr = join_group(join_args);
    UserSecretKey usk;
    usk.b0 = strToG2(jgr.b0);
    usk.b3 = strToG2(jgr.b3);
    usk.b4 = strToG2(jgr.b4);
    usk.b5 = strToG1(jgr.b5);
    string str = "123";
    get_sig_args sig_args(str, jgr.b0, jgr.b3, jgr.b4, jgr.b5);
    get_sig_return gsr = get_sig(sig_args);
    Signature sig;
    sig.c0 = strToG2(args.c0);
    sig.c5 = strToG1(args.c5);
    sig.c6 = strToG2(args.c6);
    sig.e1 = strToG1(args.e1);
    sig.e2 = strToG2(args.e2);
    sig.e3 = strToGT(args.e3);
    sig.x = strToZR(args.x);
    sig.y = strToZR(args.y);
    sig.z = strToZR(args.z);

    final.result = "123";
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
  void groupSetup(const std::string &groupID, const G2 &msk, GroupSecretKey &gsk, const MasterPublicKey &mpk) const
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
  void join(const string &groupID, const string &userID, const GroupSecretKey &gsk, UserSecretKey &usk, const MasterPublicKey &mpk) const
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
  void sign(const ZR &m, const UserSecretKey &usk, Signature &sig, const MasterPublicKey &mpk) const
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
  bool verify(const ZR &m, const Signature &sig, const string &groupID, const MasterPublicKey &mpk)
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

  ZR open(const MasterPublicKey &mpk, const GroupSecretKey &gsk, const Signature &sig)
  {
    const ZR gUserID = group.hashListToZR(getUserID());
    relicxx::GT t = group.exp(group.pair(mpk.hibeg1, mpk.g2), sig.z);
    //goes through all user identifiers here
    if (sig.e3 == group.mul(group.exp(mpk.n, gUserID), t))
      return gUserID;
    else
      return group.randomZR();
  }
  MasterPublicKey getMpk() const
  {
    relicxx::G2 msk;
    MasterPublicKey mpk;
    setup(mpk, msk);
    return mpk;
  }
  string getGroupID() const
  {
    return "science";
  }
  //可能需要多种场景
  string getUserID() const
  {
    return "www";
  }
  relicxx::G2 getMsk() const
  {
    return group.randomG2();
  }
  relicxx::G2 getGsk() const
  {
    return group.randomG2();
  }
  string g1ToStr(relicxx::G1 g) const
  {
    int len = 4 * FP_BYTES + 1;
    uint8_t bin[len];
    int l;
    l = g1_size_bin(g.g, 1);
    g1_write_bin(bin, l, g.g, 1);
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
  relicxx::G1 strToG1(string str)
  {
    relicx::G1 g;
    int len = 4 * FP_BYTES + 1;
    uint8_t bin[len];
    for (int i = 0; i < str.length(); i += 2)
    {
      std::string pair = str.substr(i, 2);
      cout << pair;
      bin2[i / 2] = ::strtol(pair.c_str(), 0, 16);
    }
    g1_read_bin(g.g, bin, l);
    return g;
  }
  string g2ToStr(relicxx::G2 g) const
  {
    int len = 4 * FP_BYTES + 1;
    uint8_t bin[len];
    int l;
    l = g2_size_bin(g.g, 1);
    g2_write_bin(bin, l, g.g, 1);

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
  relicxx::G2 strToG2(string str)
  {
    relicx::G2 g;
    int len = 4 * FP_BYTES + 1;
    uint8_t bin[len];
    for (int i = 0; i < str.length(); i += 2)
    {
      std::string pair = str.substr(i, 2);
      cout << pair;
      bin2[i / 2] = ::strtol(pair.c_str(), 0, 16);
    }
    g2_read_bin(g.g, bin, l);
    return g;
  }
  string gtToStr(relicxx::GT g) const
  {
    relicxx::GT g2;
    int len = 4 * FP_BYTES + 1;
    uint8_t bin[len];
    int l;
    l = gt_size_bin(g.g, 1);
    gt_write_bin(bin, l, g.g, 1);
    cout << "g:" << g;

    gt_read_bin(g2.g, bin, l);
    cout << "g2:" << g2;

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
  relicxx::GT strToGt(string str)
  {
    relicx::GT g;
    int len = 4 * FP_BYTES + 1;
    uint8_t bin[len];
    for (int i = 0; i < str.length(); i += 2)
    {
      std::string pair = str.substr(i, 2);
      cout << pair;
      bin2[i / 2] = ::strtol(pair.c_str(), 0, 16);
    }
    gt_read_bin(g.g, bin, l);
    return g;
  }
  string zrToStr(relicxx::ZR zr) const
  {
    int len = CEIL(RELIC_BN_BITS, 8);
    uint8_t bin[len];
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
    return str;
  }
  relicxx::ZR strToZR(string str) const
  {
    int len = CEIL(RELIC_BN_BITS, 8);
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

  char *inttohex(int a) const
  {
    char *buffer = new char[3];
    if (a / 16 < 10)
      buffer[0] = a / 16 + '0';
    else
      buffer[0] = a / 16 - 10 + 'a';
    if (a % 16 < 10)
      buffer[1] = a % 16 + '0';
    else
      buffer[1] = a % 16 - 10 + 'a';
    buffer[2] = '\0';
    return buffer;
  }
};
} // namespace detail

sig_by_key_api::sig_by_key_api() : my(new detail::sig_by_key_api_impl())
{
  JSON_RPC_REGISTER_API(STEEM_sig_by_key_api_plugin_NAME);
}

sig_by_key_api::~sig_by_key_api() {}

// 需要注意创建sig_by_key的时机，因W为sig_by_key的构造函数中会调用JSON RPC插件去注册API，因此
// 需要等JSON RPC先初始化好，plugin_initialize被调用时，会先注册sig_by_key_api_plugin的依赖
// 模块，因此可以确保此时JSON RPC插件此时已经注册完毕。
void sig_by_key_api_plugin::plugin_initialize(const appbase::variables_map &options)
{
  api = std::make_shared<sig_by_key_api>();
}

DEFINE_LOCKLESS_APIS(sig_by_key_api, (get_sig)(set_group)(join_group)(test))
} // namespace sig_by_key
} // namespace plugins
} // namespace steem
