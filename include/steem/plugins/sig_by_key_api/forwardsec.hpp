/*
 * forwardsec.hpp
 *
 *  Created on: Dec 21, 2014
 *      Author: imiers
 */

#ifndef SRC_FORWARDSEC_H_
#define SRC_FORWARDSEC_H_
#include <cereal/archives/binary.hpp>
#include <cereal/types/base_class.hpp>
#include <cereal/access.hpp>

#include "relic_api.hpp"

namespace forwardsec{
class baseKey{
public:
	relicxx::G1 g;
	relicxx::G2 g2;
	friend bool operator==(const baseKey& x, const baseKey& y){
		return (x.g == y.g && x.g2 == y.g2 );
	}
	friend bool operator!=(const baseKey& x, const baseKey& y){
		return !(x==y);
	}
};

// (from cereal documentation )Note the non-member serialize - trying to call serialize
// from a derived class wouldn't work
template <class Archive>
void serialize( Archive & ar, baseKey & b )
{ ar( b.g,b.g2 ); }

}
#endif /* SRC_FORWARDSEC_H_ */
