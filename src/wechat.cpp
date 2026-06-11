#include <Windows.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <cstdio>
#include <cstring>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

namespace {

constexpr char SQLITE_FILE_HEADER[] = "SQLite format 3";
constexpr int IV_SIZE = 16;
constexpr int HMAC_SHA1_SIZE = 20;
constexpr int KEY_SIZE = 32;
constexpr int DEFAULT_PAGESIZE = 4096;
constexpr int DEFAULT_ITER = 64000;

// Original project comment: PC pass was obtained with OllyDbg.
const unsigned char PASS[] = {
    0x53, 0xE9, 0xBF, 0xB2, 0x3B, 0x72, 0x41, 0x95,
    0xA2, 0xBC, 0x6E, 0xB5, 0xBF, 0xEB, 0x06, 0x10,
    0xDC, 0x21, 0x64, 0x75, 0x6B, 0x9B, 0x42, 0x79,
    0xBA, 0x32, 0x15, 0x76, 0x39, 0xA4, 0x0B, 0xB1,
};

std::string OutputName(const std::string& input) {
    const size_t slash = input.find_last_of("\\/");
    if (slash == std::string::npos) {
        return "dec_" + input;
    }
    return input.substr(0, slash + 1) + "dec_" + input.substr(slash + 1);
}

bool FileExists(const std::string& path) {
    DWORD attrs = GetFileAttributesA(path.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

bool ReadFileBytes(const std::string& path, std::vector<unsigned char>* bytes) {
    FILE* fp = std::fopen(path.c_str(), "rb");
    if (fp == nullptr) {
        std::cerr << "Failed to open input file.\n";
        return false;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        std::cerr << "Failed to seek input file.\n";
        return false;
    }

    const long size = ftell(fp);
    if (size <= 0) {
        fclose(fp);
        std::cerr << "Input file is empty or invalid.\n";
        return false;
    }

    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        std::cerr << "Failed to rewind input file.\n";
        return false;
    }

    bytes->resize(static_cast<size_t>(size));
    const size_t read = fread(bytes->data(), 1, bytes->size(), fp);
    fclose(fp);

    if (read != bytes->size()) {
        std::cerr << "Failed to read complete input file.\n";
        return false;
    }

    return true;
}

bool WriteAll(FILE* fp, const unsigned char* data, size_t size) {
    return fwrite(data, 1, size, fp) == size;
}

bool DecryptDb(const std::string& input) {
    std::vector<unsigned char> db;
    if (!ReadFileBytes(input, &db)) {
        return false;
    }

    if (db.size() < DEFAULT_PAGESIZE || db.size() % DEFAULT_PAGESIZE != 0) {
        std::cerr << "Input size is not aligned to the expected 4096-byte page size.\n";
        return false;
    }

    const std::string output = OutputName(input);
    if (FileExists(output)) {
        std::cerr << "Output file already exists: " << output << "\n";
        std::cerr << "Move or rename it before running again.\n";
        return false;
    }

    unsigned char salt[16] = {0};
    std::memcpy(salt, db.data(), sizeof(salt));

    unsigned char mac_salt[16] = {0};
    std::memcpy(mac_salt, salt, sizeof(mac_salt));
    for (unsigned char& value : mac_salt) {
        value ^= 0x3a;
    }

    int reserve = IV_SIZE + HMAC_SHA1_SIZE;
    reserve = ((reserve % AES_BLOCK_SIZE) == 0)
                  ? reserve
                  : ((reserve / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;

    unsigned char key[KEY_SIZE] = {0};
    unsigned char mac_key[KEY_SIZE] = {0};

    if (PKCS5_PBKDF2_HMAC_SHA1(reinterpret_cast<const char*>(PASS),
                               sizeof(PASS),
                               salt,
                               sizeof(salt),
                               DEFAULT_ITER,
                               sizeof(key),
                               key) != 1) {
        std::cerr << "Failed to derive database key.\n";
        return false;
    }

    if (PKCS5_PBKDF2_HMAC_SHA1(reinterpret_cast<const char*>(key),
                               sizeof(key),
                               mac_salt,
                               sizeof(mac_salt),
                               2,
                               sizeof(mac_key),
                               mac_key) != 1) {
        std::cerr << "Failed to derive HMAC key.\n";
        return false;
    }

    FILE* out = std::fopen(output.c_str(), "wb");
    if (out == nullptr) {
        std::cerr << "Failed to create output file.\n";
        return false;
    }

    const int page_count = static_cast<int>(db.size() / DEFAULT_PAGESIZE);
    int offset = 16;

    for (int page = 1; page <= page_count; ++page) {
        const unsigned char* encrypted_page = db.data() + ((page - 1) * DEFAULT_PAGESIZE);
        unsigned char decrypted_page[DEFAULT_PAGESIZE] = {0};

        std::cout << "Decrypting page: " << page << "/" << page_count << "\n";

        HMAC_CTX* hctx = HMAC_CTX_new();
        if (hctx == nullptr) {
            fclose(out);
            std::cerr << "Failed to allocate HMAC context.\n";
            return false;
        }
        unsigned char hash_mac[HMAC_SHA1_SIZE] = {0};
        unsigned int hash_len = 0;
        HMAC_Init_ex(hctx, mac_key, sizeof(mac_key), EVP_sha1(), nullptr);
        HMAC_Update(hctx,
                    encrypted_page + offset,
                    DEFAULT_PAGESIZE - reserve - offset + IV_SIZE);
        HMAC_Update(hctx,
                    reinterpret_cast<const unsigned char*>(&page),
                    sizeof(page));
        HMAC_Final(hctx, hash_mac, &hash_len);
        HMAC_CTX_free(hctx);

        if (std::memcmp(hash_mac,
                        encrypted_page + DEFAULT_PAGESIZE - reserve + IV_SIZE,
                        sizeof(hash_mac)) != 0) {
            fclose(out);
            std::cerr << "HMAC check failed on page " << page << ".\n";
            std::cerr << "This database may not match the old PC WeChat format.\n";
            return false;
        }

        if (page == 1) {
            std::memcpy(decrypted_page, SQLITE_FILE_HEADER, offset);
        }

        EVP_CIPHER_CTX* ectx = EVP_CIPHER_CTX_new();
        if (ectx == nullptr) {
            fclose(out);
            std::cerr << "Failed to allocate cipher context.\n";
            return false;
        }

        int len = 0;
        int total = 0;
        bool ok = true;
        ok = ok && EVP_CipherInit_ex(ectx, EVP_aes_256_cbc(), nullptr, nullptr, nullptr, 0) == 1;
        ok = ok && EVP_CIPHER_CTX_set_padding(ectx, 0) == 1;
        ok = ok && EVP_CipherInit_ex(
                       ectx,
                       nullptr,
                       nullptr,
                       key,
                       encrypted_page + (DEFAULT_PAGESIZE - reserve),
                       0) == 1;
        ok = ok && EVP_CipherUpdate(ectx,
                                    decrypted_page + offset,
                                    &len,
                                    encrypted_page + offset,
                                    DEFAULT_PAGESIZE - reserve - offset) == 1;
        total = len;
        ok = ok && EVP_CipherFinal_ex(ectx, decrypted_page + offset + len, &len) == 1;
        total += len;
        EVP_CIPHER_CTX_free(ectx);

        if (!ok || total != DEFAULT_PAGESIZE - reserve - offset) {
            fclose(out);
            std::cerr << "AES decrypt failed on page " << page << ".\n";
            return false;
        }

        std::memcpy(decrypted_page + DEFAULT_PAGESIZE - reserve,
                    encrypted_page + DEFAULT_PAGESIZE - reserve,
                    reserve);

        if (!WriteAll(out, decrypted_page, DEFAULT_PAGESIZE)) {
            fclose(out);
            std::cerr << "Failed to write output file.\n";
            return false;
        }

        offset = 0;
    }

    fclose(out);
    std::cout << "Decrypt success: " << output << "\n";
    return true;
}

}  // namespace

int main(int argc, char* argv[]) {
    std::string dbfilename;
    if (argc >= 2) {
        dbfilename = argv[1];
    } else {
        std::cout << "Input database filename: ";
        std::cin >> dbfilename;
    }

    if (dbfilename.empty()) {
        std::cerr << "No input file provided.\n";
        return 1;
    }

    return DecryptDb(dbfilename) ? 0 : 1;
}
