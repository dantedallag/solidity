/*
	This file is part of solidity.

	solidity is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	solidity is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with solidity.  If not, see <http://www.gnu.org/licenses/>.
*/
/**
 * EVM execution host, i.e. component that implements a simulated Ethereum blockchain
 * for testing purposes.
 */

#include <test/EVMHost.h>

#include <test/evmc/helpers.hpp>
#include <test/evmc/loader.h>

#include <libevmasm/GasMeter.h>

#include <libdevcore/Exceptions.h>
#include <libdevcore/Assertions.h>
#include <libdevcore/Keccak256.h>
#include <libdevcore/picosha2.h>

using namespace std;
using namespace dev;
using namespace dev::test;

namespace
{


evmc::vm& getVM()
{
	static unique_ptr<evmc::vm> theVM;
	if (!theVM)
	{
		// TODO make this an option
		for (auto path: {
			"deps/lib/libevmone.so",
			"../deps/lib/libevmone.so",
			"/usr/lib/libevmone.so",
			"/usr/local/lib/libevmone.so",
			// TODO the circleci docker image somehow only has the .a file
			"/usr/lib/libevmone.a"
		})
		{
			evmc_loader_error_code errorCode = {};
			evmc_instance* vm = evmc_load_and_create(path, &errorCode);
			if (!vm || errorCode != EVMC_LOADER_SUCCESS)
				continue;
			theVM = make_unique<evmc::vm>(vm);
			break;
		}
		if (!theVM)
		{
			cerr << "Unable to find library libevmone.so" << endl;
			assertThrow(false, Exception, "");
		}
	}
	return *theVM;
}

}


EVMHost::EVMHost(langutil::EVMVersion _evmVersion):
	m_vm(getVM())
{
	if (_evmVersion == langutil::EVMVersion::homestead())
		m_evmVersion = EVMC_HOMESTEAD;
	else if (_evmVersion == langutil::EVMVersion::tangerineWhistle())
		m_evmVersion = EVMC_TANGERINE_WHISTLE;
	else if (_evmVersion == langutil::EVMVersion::spuriousDragon())
		m_evmVersion = EVMC_SPURIOUS_DRAGON;
	else if (_evmVersion == langutil::EVMVersion::byzantium())
		m_evmVersion = EVMC_BYZANTIUM;
	else if (_evmVersion == langutil::EVMVersion::constantinople())
		m_evmVersion = EVMC_CONSTANTINOPLE;
	else //if (_evmVersion == langutil::EVMVersion::petersburg())
		m_evmVersion = EVMC_PETERSBURG;
}

evmc_storage_status EVMHost::set_storage(const evmc_address& _addr, const evmc_bytes32& _key, const evmc_bytes32& _value) noexcept
{
	evmc_bytes32 previousValue = m_state.accounts[_addr].storage[_key];
	m_state.accounts[_addr].storage[_key] = _value;

	// TODO EVMC_STORAGE_MODIFIED_AGAIN should be also used
	if (previousValue == _value)
		return EVMC_STORAGE_UNCHANGED;
	else if (previousValue == evmc_bytes32{})
		return EVMC_STORAGE_ADDED;
	else if (_value == evmc_bytes32{})
		return EVMC_STORAGE_DELETED;
	else
		return EVMC_STORAGE_MODIFIED;

}

void EVMHost::selfdestruct(const evmc_address& _addr, const evmc_address& _beneficiary) noexcept
{
	// TODO actual selfdestruct is even more complicated.
	evmc_uint256be balance = m_state.accounts[_addr].balance;
	m_state.accounts.erase(_addr);
	m_state.accounts[_beneficiary].balance = balance;
}

evmc::result EVMHost::call(evmc_message const& _message) noexcept
{
	if (_message.destination == convertToEVMC(Address(1)))
		return precompileECRecover(_message);
	else if (_message.destination == convertToEVMC(Address(2)))
		return precompileSha256(_message);
	else if (_message.destination == convertToEVMC(Address(3)))
		return precompileRipeMD160(_message);
	else if (_message.destination == convertToEVMC(Address(4)))
		return precompileIdentity(_message);
	else if (_message.destination == convertToEVMC(Address(5)))
		return precompileModExp(_message);
	else if (_message.destination == convertToEVMC(Address(6)))
		return precompileALTBN128G1Add(_message);
	else if (_message.destination == convertToEVMC(Address(7)))
		return precompileALTBN128G1Mul(_message);
	else if (_message.destination == convertToEVMC(Address(8)))
		return precompileALTBN128PairingProduct(_message);

	State stateBackup = m_state;

	u256 value{convertFromEVMC(_message.value)};
	Account& sender = m_state.accounts[_message.sender];

	bytes code;

	evmc_message message = _message;
	if (message.depth == 0)
	{
		message.gas -= message.kind == EVMC_CREATE ? eth::GasCosts::txCreateGas : eth::GasCosts::txGas;
		for (size_t i = 0; i < message.input_size; ++i)
			message.gas -= message.input_data[i] == 0 ? eth::GasCosts::txDataZeroGas : eth::GasCosts::txDataNonZeroGas;
		if (message.gas < 0)
		{
			evmc::result result({});
			result.status_code = EVMC_OUT_OF_GAS;
			m_state = stateBackup;
			return result;
		}
	}

	if (message.kind == EVMC_CREATE)
	{
		// TODO this is not the right formula
		// TODO is the nonce incremented on failure, too?
		Address createAddress(keccak256(
			bytes(begin(message.sender.bytes), end(message.sender.bytes)) +
			asBytes(to_string(sender.nonce++))
		));
		message.destination = convertToEVMC(createAddress);
		code = bytes(message.input_data, message.input_data + message.input_size);
	}
	else if (message.kind == EVMC_DELEGATECALL)
	{
		code = m_state.accounts[message.destination].code;
		message.destination = m_currentAddress;
	}
	else if (message.kind == EVMC_CALLCODE)
	{
		code = m_state.accounts[message.destination].code;
		message.destination = m_currentAddress;
	}
	else
		code = m_state.accounts[message.destination].code;
	//TODO CREATE2

	Account& destination = m_state.accounts[message.destination];

	if (value != 0 && message.kind != EVMC_DELEGATECALL && message.kind != EVMC_CALLCODE)
	{
		sender.balance = convertToEVMC(u256(convertFromEVMC(sender.balance)) - value);
		destination.balance = convertToEVMC(u256(convertFromEVMC(destination.balance)) + value);
	}

	evmc_address currentAddress = m_currentAddress;
	m_currentAddress = message.destination;
	evmc::result result = m_vm.execute(*this, m_evmVersion, message, code.data(), code.size());
	m_currentAddress = currentAddress;

	if (message.kind == EVMC_CREATE)
	{
		result.gas_left -= eth::GasCosts::createDataGas * result.output_size;
		if (result.gas_left < 0)
		{
			result.gas_left = 0;
			result.status_code = EVMC_OUT_OF_GAS;
			// TODO clear some fields?
		}
		else
		{
			result.create_address = message.destination;
			destination.code = bytes(result.output_data, result.output_data + result.output_size);
			destination.codeHash = convertToEVMC(keccak256(destination.code));
		}
	}

	if (result.status_code != EVMC_SUCCESS)
		m_state = stateBackup;

	return result;
}

evmc_tx_context EVMHost::get_tx_context() noexcept
{
	evmc_tx_context ctx = {};
	ctx.block_timestamp = m_state.timestamp;
	ctx.block_number = m_state.blockNumber;
	ctx.block_coinbase = m_coinbase;
	ctx.block_difficulty = convertToEVMC(u256("200000000"));
	ctx.block_gas_limit = 20000000;
	ctx.tx_gas_price = convertToEVMC(u256("3000000000"));
	ctx.tx_origin = convertToEVMC(Address("0x9292929292929292929292929292929292929292"));
	return ctx;
}

evmc_bytes32 EVMHost::get_block_hash(int64_t _number) noexcept
{
	return convertToEVMC(u256("0x3737373737373737373737373737373737373737373737373737373737373737") + _number);
}

void EVMHost::emit_log(
	evmc_address const& _addr,
	uint8_t const* _data,
	size_t _dataSize,
	evmc_bytes32 const _topics[],
	size_t _topicsCount
) noexcept
{
	LogEntry entry;
	entry.address = convertFromEVMC(_addr);
	for (size_t i = 0; i < _topicsCount; ++i)
		entry.topics.emplace_back(convertFromEVMC(_topics[i]));
	entry.data = bytes(_data, _data + _dataSize);
	m_state.logs.emplace_back(std::move(entry));
}


Address EVMHost::convertFromEVMC(evmc_address const& _addr)
{
	return Address(bytes(begin(_addr.bytes), end(_addr.bytes)));
}

evmc_address EVMHost::convertToEVMC(Address const& _addr)
{
	evmc_address a;
	for (size_t i = 0; i < 20; ++i)
		a.bytes[i] = _addr[i];
	return a;
}

h256 EVMHost::convertFromEVMC(evmc_bytes32 const& _data)
{
	return h256(bytes(begin(_data.bytes), end(_data.bytes)));
}

evmc_bytes32 EVMHost::convertToEVMC(h256 const& _data)
{
	evmc_bytes32 d;
	for (size_t i = 0; i < 32; ++i)
		d.bytes[i] = _data[i];
	return d;
}

evmc::result EVMHost::precompileECRecover(evmc_message const& _message) noexcept
{
	bytes static data;
	data = bytes(_message.input_data, _message.input_data + _message.input_size);

	// Some fixed inputs...
	if (data == fromHex(
		"18c547e4f7b0f325ad1e56f57e26c745b09a3e503d86e00e5255ff7f715d3d1c"
		"000000000000000000000000000000000000000000000000000000000000001c"
		"73b1693892219d736caba55bdb67216e485557ea6b6af75f37096c9aa6a5a75f"
		"eeb940b1d03b21e36b0e47e79769f095fe2ab855bd91e3a38756b7d75a9c4549"
	))
		data = fromHex("000000000000000000000000a94f5374fce5edbc8e2a8697c15331677e6ebf0b");
	else if (data == fromHex(
		"47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad"
		"000000000000000000000000000000000000000000000000000000000000001c"
		"debaaa0cddb321b2dcaaf846d39605de7b97e77ba6106587855b9106cb104215"
		"61a22d94fa8b8a687ff9c911c844d1c016d1a685a9166858f9c7c1bc85128aca"
	))
		data = fromHex("0000000000000000000000008743523d96a1b2cbe0c6909653a56da18ed484af");
	else
		data = {};

	// TODO this and the above is shared among the precompiles...
	evmc::result result({});
	result.output_data = data.data();
	result.output_size = data.size();
	return result;
}

evmc::result EVMHost::precompileSha256(evmc_message const& _message) noexcept
{
	// static data so that we do not need a release routine...
	bytes static hash;
	hash = picosha2::hash256(bytes(
		_message.input_data,
		_message.input_data + _message.input_size
	));

	evmc::result result({});
	result.output_data = hash.data();
	result.output_size = hash.size();
	return result;
}

evmc::result EVMHost::precompileRipeMD160(evmc_message const& _message) noexcept
{
	bytes static data;
	data = bytes(_message.input_data, _message.input_data + _message.input_size);

	// Some fixed inputs...
	if (data.empty())
		data = fromHex("0000000000000000000000009c1185a5c5e9fc54612808977ee8f548b2258d31");
	else if (data == fromHex("0000000000000000000000000000000000000000000000000000000000000004"))
		data = fromHex("0000000000000000000000001b0f3c404d12075c68c938f9f60ebea4f74941a0");
	else if (data == fromHex("0000000000000000000000000000000000000000000000000000000000000005"))
		data = fromHex("000000000000000000000000ee54aa84fc32d8fed5a5fe160442ae84626829d9");
	else if (data == fromHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"))
		data = fromHex("0000000000000000000000001cf4e77f5966e13e109703cd8a0df7ceda7f3dc3");
	else if (data == fromHex("0000000000000000000000000000000000000000000000000000000000000000"))
		data = fromHex("000000000000000000000000f93175303eba2a7b372174fc9330237f5ad202fc");
	else if (data == fromHex(
		"0800000000000000000000000000000000000000000000000000000000000000"
		"0401000000000000000000000000000000000000000000000000000000000000"
		"0000000400000000000000000000000000000000000000000000000000000000"
		"00000100"
	))
		data = fromHex("000000000000000000000000f93175303eba2a7b372174fc9330237f5ad202fc");
	else if (data == fromHex(
		"0800000000000000000000000000000000000000000000000000000000000000"
		"0501000000000000000000000000000000000000000000000000000000000000"
		"0000000500000000000000000000000000000000000000000000000000000000"
		"00000100"
	))
		data = fromHex("0000000000000000000000004f4fc112e2bfbe0d38f896a46629e08e2fcfad5");
	else if (data == fromHex(
		"08ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		"ff010000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		"ffffffff00000000000000000000000000000000000000000000000000000000"
		"00000100"
	))
		data = fromHex("000000000000000000000000c0a2e4b1f3ff766a9a0089e7a410391730872495");
	else if (data == fromHex(
		"6162636465666768696a6b6c6d6e6f707172737475767778797a414243444546"
		"4748494a4b4c4d4e4f505152535455565758595a303132333435363738393f21"
	))
		data = fromHex("00000000000000000000000036c6b90a49e17d4c1e1b0e634ec74124d9b207da");
	else if (data == fromHex("6162636465666768696a6b6c6d6e6f707172737475767778797a414243444546"))
		data = fromHex("000000000000000000000000ac5ab22e07b0fb80c69b6207902f725e2507e546");
	else
		data = {};
	evmc::result result({});
	result.output_data = data.data();
	result.output_size = data.size();
	return result;
}

evmc::result EVMHost::precompileIdentity(evmc_message const& _message) noexcept
{
	// static data so that we do not need a release routine...
	bytes static data;
	data = bytes(_message.input_data, _message.input_data + _message.input_size);
	evmc::result result({});
	result.output_data = data.data();
	result.output_size = data.size();
	return result;
}

evmc::result EVMHost::precompileModExp(evmc_message const&) noexcept
{
	// TODO implement
	evmc::result result({});
	return result;
}

evmc::result EVMHost::precompileALTBN128G1Add(evmc_message const&) noexcept
{
	// TODO implement
	evmc::result result({});
	return result;
}

evmc::result EVMHost::precompileALTBN128G1Mul(evmc_message const&) noexcept
{
	// TODO implement
	evmc::result result({});
	return result;
}

evmc::result EVMHost::precompileALTBN128PairingProduct(evmc_message const&) noexcept
{
	// TODO implement
	evmc::result result({});
	return result;
}

