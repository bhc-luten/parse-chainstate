#include "dbwrapper.h"
#include "utilities.h"

DBWrapper::DBWrapper(std::string _dbName) : dbName(_dbName)
{
	try {
		options = leveldb::Options();
		openDB();
	} catch (const std::invalid_argument& e) {
		std::cerr << e.what() << '\n';
		exit(EXIT_FAILURE);
	} catch (const char* msg) {
		std::cerr << msg << '\n';
		exit(EXIT_FAILURE);
	}
	setObfuscationKey();
}

DBWrapper::~DBWrapper()
{
	delete db;
}

/**
 * Build the key needed to fetch the obfuscation key: `obfuscationKeyKey`.
 *
 * This is stored as a value in the database with the byte values {0x0e, 0x00}
 * prepended to the string "obfuscate_key".
 * The first character of the retrieved obfuscationKey is 0x08 and should be removed.
 * */
void DBWrapper::setObfuscationKey()
{
	obfuscationKeyKey = {0x0e, 0x00};
	obfuscationKeyKey += "obfuscate_key";
	std::string obfuscationKeyString;
	read(obfuscationKeyKey, obfuscationKeyString);
	utilities::stringToHexBytes(obfuscationKeyString, obfuscationKey);
	obfuscationKey.erase(obfuscationKey.begin());
	// obfuscation key loaded successfully
}

void DBWrapper::openDB()
{
	if (dbName.empty()) {
		throw std::invalid_argument{"No database specified in DBWrapper::openDB()"};
	}

	// Check that the provided path exists and do a basic sanity check that it looks like a LevelDB database.
	// Some copied chainstate directories may not contain a LOG file, so accept CURRENT or a MANIFEST file.
	std::filesystem::path p = dbName;
	const bool has_current = std::filesystem::exists(p / "CURRENT");
	bool has_manifest = false;
	for (const auto& entry : std::filesystem::directory_iterator(p)) {
		if (entry.path().filename().string().rfind("MANIFEST-", 0) == 0) {
			has_manifest = true;
			break;
		}
	}
	if (!has_current && !has_manifest) {
		throw "The provided path is not a LevelDB database.";
	}
	
	leveldb::Status status = leveldb::DB::Open(options, dbName, &db);
	if (!status.ok()) {
		throw "Can't open the specified database.";
	}
	readoptions.verify_checksums = true;
}

void DBWrapper::setDBName(const std::string& s)
{
	dbName = s;
}

void DBWrapper::read(std::string const& key, std::string& val)
{
	status = db->Get(readoptions, key, &val);
	checkStatus("Error reading obfuscation key");
}

void DBWrapper::checkStatus(std::string msg)
{
	if (!status.ok()) {
		std::cerr << msg << "\n";
		std::cerr << status.ToString() << std::endl;
	}
	assert(status.ok());
}

/**
 *
 * */
void DBWrapper::getAllUTXOs(std::vector<UTXO>& utxos)
{
	leveldb::Iterator* it = db->NewIterator(readoptions);
	for (it->SeekToFirst(); it->Valid(); it->Next()) {

		BytesVec key;
		for (size_t i = 0; i < it->key().size(); i++) {
			key.push_back(it->key()[i]);
		} 
		if (key[0] == 0x43) {
			BytesVec deObfuscatedValue;
			deObfuscate(it->value(), deObfuscatedValue);
			Varint v(deObfuscatedValue);
			UTXO u(v);
			BytesVec txid;
			assert(key.size() > 33);
			txid.insert(txid.begin(), key.begin() + 1, key.begin() + 33);
			utilities::switchEndianness(txid);
			u.setTXID(txid);
			utxos.push_back(u);
		}
	}
	assert(it->status().ok());
	delete it;
}

static uint64_t read_chainstate_varint(const BytesVec& buf, size_t& pos)
{
	uint64_t n = 0;
	while (pos < buf.size()) {
		unsigned char ch = buf[pos++];
		n = (n << 7) | (ch & 0x7F);
		if (ch & 0x80) {
			n += 1;
		} else {
			return n;
		}
	}
	throw std::runtime_error("unexpected EOF in chainstate varint");
}

static uint64_t decompress_amount_direct(uint64_t x)
{
	if (x == 0) return 0;
	x -= 1;
	int e = x % 10;
	x /= 10;
	uint64_t n = 0;
	if (e < 9) {
		int d = (x % 9) + 1;
		x /= 9;
		n = x * 10 + d;
	} else {
		n = x + 1;
	}
	while (e) {
		n *= 10;
		e -= 1;
	}
	return n;
}

static std::string hexstr(const BytesVec& bytes)
{
	std::string s;
	utilities::bytesToHexstring(bytes, s);
	return s;
}

static uint64_t decode_key_vout(const BytesVec& key)
{
	size_t pos = 33;
	return read_chainstate_varint(key, pos);
}

static bool decode_script_direct(const BytesVec& raw, size_t& pos, std::string& kind, BytesVec& script)
{
	uint64_t nsize = read_chainstate_varint(raw, pos);
	if (nsize == 0) {
		if (pos + 20 > raw.size()) return false;
		script = {0x76, 0xa9, 0x14};
		script.insert(script.end(), raw.begin() + pos, raw.begin() + pos + 20);
		script.push_back(0x88);
		script.push_back(0xac);
		pos += 20;
		kind = "p2pkh";
		return true;
	}
	if (nsize == 1) {
		if (pos + 20 > raw.size()) return false;
		script = {0xa9, 0x14};
		script.insert(script.end(), raw.begin() + pos, raw.begin() + pos + 20);
		script.push_back(0x87);
		pos += 20;
		kind = "p2sh";
		return true;
	}
	if (nsize == 2 || nsize == 3) {
		if (pos + 32 > raw.size()) return false;
		script = {0x21, static_cast<unsigned char>(nsize)};
		script.insert(script.end(), raw.begin() + pos, raw.begin() + pos + 32);
		script.push_back(0xac);
		pos += 32;
		kind = "p2pk_compressed";
		return true;
	}
	if (nsize == 4 || nsize == 5) {
		if (pos + 32 > raw.size()) return false;
		script.clear();
		script.push_back(0x41);
		script.push_back(static_cast<unsigned char>(nsize - 2));
		script.insert(script.end(), raw.begin() + pos, raw.begin() + pos + 32);
		script.push_back(0xac);
		pos += 32;
		kind = "p2pk_uncompressed_special";
		return true;
	}
	uint64_t script_len = nsize - 6;
	if (pos + script_len > raw.size()) return false;
	script.assign(raw.begin() + pos, raw.begin() + pos + script_len);
	pos += script_len;
	auto all_zero_after = [&](size_t start) {
		for (size_t i = start; i < script.size(); ++i) {
			if (script[i] != 0x00) return false;
		}
		return true;
	};
	if (script.size() == 22 && script[0] == 0x00 && script[1] == 0x14) {
		kind = all_zero_after(2) ? "raw" : "p2wpkh";
	}
	else if (script.size() == 34 && script[0] == 0x00 && script[1] == 0x20) {
		kind = all_zero_after(2) ? "raw" : "p2wsh";
	}
	else if (script.size() == 34 && script[0] == 0x51 && script[1] == 0x20) {
		kind = all_zero_after(2) ? "raw" : "p2tr";
	}
	else kind = "raw";
	return true;
}

void DBWrapper::printAllUTXOs()
{
	leveldb::Iterator* it = db->NewIterator(readoptions);
	for (it->SeekToFirst(); it->Valid(); it->Next()) {
		BytesVec key;
		for (size_t i = 0; i < it->key().size(); i++) key.push_back(it->key()[i]);
		if (key.empty() || key[0] != 0x43) continue;
		BytesVec raw;
		deObfuscate(it->value(), raw);
		size_t pos = 0;
		uint64_t code = read_chainstate_varint(raw, pos);
		uint64_t height = code >> 1;
		uint64_t coinbase = code & 1;
		uint64_t amount = decompress_amount_direct(read_chainstate_varint(raw, pos));
		std::string kind;
		BytesVec script;
		if (!decode_script_direct(raw, pos, kind, script)) continue;
		BytesVec txid;
		txid.insert(txid.begin(), key.begin() + 1, key.begin() + 33);
		utilities::switchEndianness(txid);
		uint64_t vout = decode_key_vout(key);
		std::cout << hexstr(txid) << "," << vout << "," << height << "," << coinbase << "," << amount << "," << hexstr(script) << "," << kind << "\n";
	}
	assert(it->status().ok());
	delete it;
}

void DBWrapper::printFirstStandardUTXOs(size_t limit)
{
	leveldb::Iterator* it = db->NewIterator(readoptions);
	size_t printed = 0;
	for (it->SeekToFirst(); it->Valid() && printed < limit; it->Next()) {
		BytesVec key;
		for (size_t i = 0; i < it->key().size(); i++) key.push_back(it->key()[i]);
		if (key.empty() || key[0] != 0x43) continue;
		BytesVec raw;
		deObfuscate(it->value(), raw);
		size_t pos = 0;
		uint64_t code = read_chainstate_varint(raw, pos);
		uint64_t height = code >> 1;
		uint64_t coinbase = code & 1;
		uint64_t amount = decompress_amount_direct(read_chainstate_varint(raw, pos));
		std::string kind;
		BytesVec script;
		if (!decode_script_direct(raw, pos, kind, script)) continue;
		if (!(kind == "p2pkh" || kind == "p2sh" || kind == "p2wpkh")) continue;
		BytesVec txid;
		txid.insert(txid.begin(), key.begin() + 1, key.begin() + 33);
		utilities::switchEndianness(txid);
		uint64_t vout = decode_key_vout(key);
		std::cout << hexstr(txid) << "," << vout << "," << height << "," << coinbase << "," << amount << "," << hexstr(script) << "," << kind << "\n";
		printed++;
	}
	assert(it->status().ok());
	delete it;
}

/**
 * Fetch a record from the LevelDB database chainstate.
 *
 * The key should be a little-endian representation of the txid bytes, prepended by the byte 0x43
 * and appended with the value of the vout of the specific UTXO.
 *
 * uint32_t seems like overkill for the vout data-type, but this is the type used by Core -
 * see: https://developer.bitcoin.org/reference/transactions.html
 * */
static std::vector<unsigned char> encode_chainstate_varint(uint64_t n)
{
	std::vector<unsigned char> out{static_cast<unsigned char>(n & 0x7F)};
	n >>= 7;
	while (n) {
		n -= 1;
		out.push_back(static_cast<unsigned char>(0x80 | (n & 0x7F)));
		n >>= 7;
	}
	std::reverse(out.begin(), out.end());
	return out;
}

void DBWrapper::fetchRecord(const std::string& txid, const uint32_t vout, BytesVec& value)
{
	std::vector<char> keyBytes;
	utilities::hexstringToBytes(txid, keyBytes);
	utilities::switchEndianness(keyBytes);
	keyBytes.insert(keyBytes.begin(), 0x43);
	auto voutBytes = encode_chainstate_varint(vout);
	for (auto b : voutBytes) keyBytes.push_back(static_cast<char>(b));
	leveldb::Slice keySlice(keyBytes.data(), keyBytes.size());
	std::string rawVal;
	
	status = db->Get(readoptions, keySlice, &rawVal);
	if (!status.ok()) {
		throw std::invalid_argument("Key not found.");
	}
	deObfuscate(rawVal, value);
}

void DBWrapper::fetchRecord(const std::string& txid, const uint32_t vout, std::string& value)
{
	BytesVec deObBytes;
	fetchRecord(txid, vout, deObBytes);
	utilities::bytesToHexstring(deObBytes, value);
}
