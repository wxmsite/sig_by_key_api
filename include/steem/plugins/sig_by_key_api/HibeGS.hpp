/*
 * @Author: wxmsite
 * @LastEditors: wxmsite
 * @Description: 
 * @Date: 2019-03-17 14:59:48
 * @LastEditTime: 2019-03-27 17:01:32
 */
#include "relic_api.hpp"
#include "forwardsec.hpp"
using namespace std;
namespace forwardsec
{
class GMPfse;
class HibeGS;

class MasterPublicKey : public virtual baseKey
{

  public:
	MasterPublicKey(){};
	~MasterPublicKey(){};
	friend bool operator==(const MasterPublicKey &x, const MasterPublicKey &y)
	{
		return ((baseKey)x == (baseKey)y &&
				x.l == y.l && x.hibeg1 == y.hibeg1 && x.hG2 == y.hG2 && x.n == y.n);
	}
	friend bool operator!=(const MasterPublicKey &x, const MasterPublicKey &y)
	{
		return !(x == y);
	}

	unsigned int l;
	relicxx::G1 hibeg1;
	vector<relicxx::G2> hG2;
	relicxx::GT n;
	template <class Archive>
	void serialize(Archive &ar)
	{
		ar(::cereal::virtual_base_class<baseKey>(this),
		   l, hibeg1, hG2, n);
	}
	friend class ::cereal::access;
	friend class GMPfse;
	friend class HibeGS;
};

class GroupSecretKey
{
  public:
	friend bool operator==(const GroupSecretKey &x, const GroupSecretKey &y)
	{
		return (x.a0 == y.a0 && x.a2 == y.a2 && x.a3 == y.a3 && x.a4 == y.a4 && x.a5 == y.a5);
	}
	friend bool operator!=(const GroupSecretKey &x, const GroupSecretKey &y)
	{
		return !(x == y);
	}
	void neuter();

  protected:
	relicxx::G2 a0;
	relicxx::G2 a2;
	relicxx::G2 a3;
	relicxx::G2 a4;
	relicxx::G1 a5;
	template <class Archive>
	void serialize(Archive &ar)
	{
		ar(a0, a2, a3, a4, a5);
	}
	friend class ::cereal::access;
	friend class GMPfse;
	friend class HibeGS;
};

class UserSecretKey
{
  public:
	friend bool operator==(const UserSecretKey &x, const UserSecretKey &y)
	{
		return (x.b0 == y.b0 && x.b3 == y.b3 && x.b4 == y.b4 && x.b5 == y.b5);
	}
	friend bool operator!=(const UserSecretKey &x, const UserSecretKey &y)
	{
		return !(x == y);
	}
	void neuter();

	relicxx::G2 b0;
	relicxx::G2 b3;
	relicxx::G2 b4;
	relicxx::G1 b5;
	template <class Archive>
	void serialize(Archive &ar)
	{
		ar(b0, b3, b4, b5);
	}
	friend class ::cereal::access;
	friend class GMPfse;
	friend class HibeGS;
};
/**
 * @description: 
 * @param {type} 
 * @return: 
 */
class Sig
{
  public:
	friend bool operator==(const Sig &x, const Sig &y)
	{
		return (x.c0 == y.c0 && x.c5 == y.c5 && x.c6 == y.c6 && x.e1 == y.e1 && x.e2 == y.e2 && x.e3 == y.e3 &&
				x.x == y.x && x.y == y.y && x.z == y.z);
	}
	friend bool operator!=(const Sig &x, const Sig &y)
	{
		return !(x == y);
	}
	void neuter();

	relicxx::G2 c0;
	relicxx::G1 c5;
	relicxx::G2 c6;
	relicxx::G1 e1;
	relicxx::G2 e2;
	relicxx::GT e3;
	relicxx::ZR x;
	relicxx::ZR y;
	relicxx::ZR z;
	template <class Archive>
	void serialize(Archive &ar)
	{
		ar(c0, c5, c6, e1, e2, e3);
	}
	friend class ::cereal::access;
	friend class GMPfse;
	friend class HibeGS;
};

class HibeGS
{
  public:
	HibeGS(){};
	~HibeGS(){};
	/**
  * @description: The trusted authority generates its mpk and msk
  * @param {
	* mpk, master public key,
	*  msk,master secret key
	* } 
  * @return: 
  */
	void setup(MasterPublicKey &mpk, relicxx::G2 &msk) const;

	bool groupSetup(const string &groupID);
	/**
  * @description: use mpk,msk and GroupID to generate a group with gsk(a0,a2,a3,a4,a5)
  * @param {
	* GroupID:group id,
	*  msk:master secret  key,
	*  gsk:group secret key
	*  mpk:master public key
	* } 
  * @return: 
  */
	void groupSetup(const string &groupID, const relicxx::G2 &msk, GroupSecretKey &gsk, const MasterPublicKey &mpk);
	/**
  * @description: 
  * @param {
	* UserID:user id,
	* usk:user secret key
	} 
  * @return: 
  */
	bool join(const string &groupID, const string &userID);
	void join(const string &groupID, const string &userID, const GroupSecretKey &gsk, UserSecretKey &usk, const MasterPublicKey &mpk);

	void sign(const string message);
	/**
  * @description: 
  * @param {
	* m:the message to be signed,
	* usk:user secret key
	* sig: the signature
	* } 
  * @return: 
  */
	void sign(const relicxx::ZR &m, const UserSecretKey &usk, Sig &sig, const MasterPublicKey &mpk);
	/**
  * @description: 
  * @param {type} 
  * @return: 
  */
	bool verify(const relicxx::ZR &m, const Sig &sig, const string &groupID, const MasterPublicKey &mpk);
	/**
  * @description: The Group Manager goes through all user identifiers and find the one who signed m
  * @param {type} 
  * @return: 
  */
	relicxx::ZR open(const MasterPublicKey &mpk, const GroupSecretKey &gsk, const Sig &sig);
	/**
 * @description: 
 * @param {null} 
 * @return: 
 */
	string getGroupID();
	/**
  * @description: 
  * @param {null} 
  * @return: 
  */
	string getUserID();

	vector<string> getGroupMember(string groupID);

	MasterPublicKey getMpk();

	relicxx::G2 getMsk();

	UserSecretKey getUsk();

	relicxx::G2 getRpk();
	relicxx::G2 getRsk();
	/*注册读者身份，本地产生公私钥对，称为rpk，rsk，本地生成公私钥对需要另用算法，而且是为了安全考虑，
然后提交个人信息及公钥到区块链，所有人上来都只能注册读者身份，要审稿必须经过认证，
要提交论文看需求决定是否需要认证,讨论下是否可以基于steem修改
*/
	void register_reader();

	//认证对应方向的审稿人身份,或者钦定，或者已经存在了群组，后续的人直接加入
	void authenticate_reviewer();

	/*投票选出主席,并且将gsk交给主席
信任中心（即我们，当然受监督）提前生成gsk，每一个人认证审稿人身份时就直接把usk给他，
选出主席后将gsk交给主席
注意：
每个审稿人共拥有两对公私钥对
1.rpk、rsk，用对消息的加密
2.（userID,usk)，用于签名
*/
	void vote_chairman();

	/*
提交论文者需要加入论文对应方向比如计算机的群，加入后主席将论文提交者的usk返回，
然后作者将自己的rpk和群签名（tx1）以及自己的rsk对id签名发送过去
每个论文提交者共拥有两对公私钥对
1.rpk、rsk，用于消息的加密和签名
2.提交论文的（userID,usk）用于签名
每个人最多有三对公私钥对
1.rpk,rsk
2.作为审稿人的公私钥对（userID,usk1)
3.作为论文提交者的公私钥对（userID，usk2）
*/
	void submit_paper(const string &userID, relicxx::G2 b0, relicxx::G2 b3, relicxx::G2 b4, relicxx::G1 b5);
	string g1ToStr(relicxx::G1 g);
	string g2ToStr(relicxx::G2 g);
};
} // namespace forwardsec