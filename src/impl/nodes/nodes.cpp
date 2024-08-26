#include <stdexcept>
#include "nodes.h"
#include "serialize.h"

using namespace talk::nodes;

Node::Node(const bytes& data){
	if (data.size() < 2){
		throw std::invalid_argument("Data is too small to be a node");
	}
	switch (serialize::deserialize_u16({data[0], data[1]})){
		case 0x00:
			// Empty node (base class)
			break;
		default:
			throw std::invalid_argument("Unknown node type");
	}

}
