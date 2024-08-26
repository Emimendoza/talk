#ifndef TALK_NODES_H
#define TALK_NODES_H
#include "common.h"
#include <memory>

namespace talk::nodes{
	class Node{
	private:
		static constinit const uint16_t type = 0x00;
	public:
		explicit Node(const bytes& data);
		virtual uint16_t getType() = 0;
		virtual bytes serialize() = 0;
	};

	// Used to announce the creation of a new certificate/user
	class NewCert : public Node{
	public:
		enum class CertOwner : uint8_t {
			USER = 0x01,
			SERVER = 0x02
		};

		enum class CertType : uint16_t {
			ED25519 = 0x01
		};
	private:
		CertOwner c_owner;
		CertType c_type;
		uint8_t revoked;
		uint64_t revocation_date;

		static constinit const uint16_t type = 0x01;
	public:

		explicit NewCert(const bytes& data);
		explicit NewCert(const CertOwner& owner, const CertType& type);
		uint16_t getType() override;
		bytes serialize() override;
	};


}

#endif //TALK_NODES_H
