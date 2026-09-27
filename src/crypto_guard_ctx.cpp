#include "crypto_guard_ctx.h"

#include <array>
#include <iomanip>
#include <memory>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <sstream>
#include <stdexcept>

namespace CryptoGuard {

namespace {

struct AesCipherParams {
    static const size_t KEY_SIZE = 32;             // AES-256 key size
    static const size_t IV_SIZE = 16;              // AES block size (IV length)
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

    int encrypt;                              // 1 for encryption, 0 for decryption
    std::array<unsigned char, KEY_SIZE> key;  // Encryption key
    std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
};

struct CipherCtxDeleter {
    void operator()(EVP_CIPHER_CTX *ctx) const {
        if (ctx) {
            EVP_CIPHER_CTX_free(ctx);
        }
    }
};

struct MdCtxDeleter {
    void operator()(EVP_MD_CTX *ctx) const {
        if (ctx) {
            EVP_MD_CTX_free(ctx);
        }
    }
};

using CipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, CipherCtxDeleter>;
using MdCtxPtr = std::unique_ptr<EVP_MD_CTX, MdCtxDeleter>;

std::string GetOpenSSLError() {
    unsigned long err = ERR_get_error();
    if (err == 0) {
        return "Unknown OpenSSL error";
    }
    char buf[256];
    ERR_error_string_n(err, buf, sizeof(buf));
    return std::string(buf);
}

}  // namespace

class CryptoGuardCtx::Impl {
public:
    Impl() { OpenSSL_add_all_algorithms(); }
    ~Impl() { EVP_cleanup(); }

    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password);
    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password);
    std::string CalculateChecksum(std::iostream &inStream);

private:
    static AesCipherParams CreateCipherParamsFromPassword(std::string_view password);

    void ProcessCipher(std::iostream &inStream, std::iostream &outStream, std::string_view password, bool encrypt);
};

AesCipherParams CryptoGuardCtx::Impl::CreateCipherParamsFromPassword(std::string_view password) {
    AesCipherParams params;
    constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

    int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                params.key.data(), params.iv.data());

    if (result == 0) {
        throw std::runtime_error{"Failed to create a key from password"};
    }

    return params;
}

void CryptoGuardCtx::Impl::ProcessCipher(std::iostream &inStream, std::iostream &outStream, std::string_view password,
                                         bool encrypt) {
    if (!inStream.good()) {
        throw std::runtime_error("Input stream is in a bad state");
    }
    if (!outStream.good()) {
        throw std::runtime_error("Output stream is in a bad state");
    }

    auto params = CreateCipherParamsFromPassword(password);
    params.encrypt = encrypt ? 1 : 0;

    CipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        throw std::runtime_error("Failed to create cipher context: " + GetOpenSSLError());
    }

    if (EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt) !=
        1) {
        throw std::runtime_error("Failed to initialize cipher: " + GetOpenSSLError());
    }

    constexpr size_t BUFFER_SIZE = 4096;
    std::array<unsigned char, BUFFER_SIZE> inBuf{};
    std::array<unsigned char, BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH> outBuf{};

    while (inStream.good()) {
        inStream.read(reinterpret_cast<char *>(inBuf.data()), BUFFER_SIZE);
        std::streamsize bytesRead = inStream.gcount();

        if (bytesRead > 0) {
            int outLen = 0;
            if (EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen, inBuf.data(), static_cast<int>(bytesRead)) != 1) {
                throw std::runtime_error("Failed to process data: " + GetOpenSSLError());
            }
            outStream.write(reinterpret_cast<char *>(outBuf.data()), outLen);
            if (!outStream.good()) {
                throw std::runtime_error("Failed to write to output stream");
            }
        }
    }

    if (inStream.bad()) {
        throw std::runtime_error("Error reading from input stream");
    }

    int outLen = 0;
    if (EVP_CipherFinal_ex(ctx.get(), outBuf.data(), &outLen) != 1) {
        throw std::runtime_error(std::string("Failed to finalize ") + (encrypt ? "encryption" : "decryption") + ": " +
                                 GetOpenSSLError());
    }
    outStream.write(reinterpret_cast<char *>(outBuf.data()), outLen);
    if (!outStream.good()) {
        throw std::runtime_error("Failed to write final block to output stream");
    }
}

void CryptoGuardCtx::Impl::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    ProcessCipher(inStream, outStream, password, true);
}

void CryptoGuardCtx::Impl::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    ProcessCipher(inStream, outStream, password, false);
}

std::string CryptoGuardCtx::Impl::CalculateChecksum(std::iostream &inStream) {
    if (!inStream.good()) {
        throw std::runtime_error("Input stream is in a bad state");
    }

    MdCtxPtr ctx(EVP_MD_CTX_new());
    if (!ctx) {
        throw std::runtime_error("Failed to create message digest context: " + GetOpenSSLError());
    }

    if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1) {
        throw std::runtime_error("Failed to initialize SHA-256: " + GetOpenSSLError());
    }

    constexpr size_t BUFFER_SIZE = 4096;
    std::array<unsigned char, BUFFER_SIZE> buffer{};

    while (inStream.good()) {
        inStream.read(reinterpret_cast<char *>(buffer.data()), BUFFER_SIZE);
        std::streamsize bytesRead = inStream.gcount();

        if (bytesRead > 0) {
            if (EVP_DigestUpdate(ctx.get(), buffer.data(), static_cast<size_t>(bytesRead)) != 1) {
                throw std::runtime_error("Failed to update digest: " + GetOpenSSLError());
            }
        }
    }

    if (inStream.bad()) {
        throw std::runtime_error("Error reading from input stream");
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLen = 0;
    if (EVP_DigestFinal_ex(ctx.get(), hash, &hashLen) != 1) {
        throw std::runtime_error("Failed to finalize digest: " + GetOpenSSLError());
    }

    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < hashLen; ++i) {
        ss << std::setw(2) << static_cast<int>(hash[i]);
    }

    return ss.str();
}

CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<Impl>()) {}

CryptoGuardCtx::~CryptoGuardCtx() = default;

CryptoGuardCtx::CryptoGuardCtx(CryptoGuardCtx &&) noexcept = default;
CryptoGuardCtx &CryptoGuardCtx::operator=(CryptoGuardCtx &&) noexcept = default;

void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->EncryptFile(inStream, outStream, password);
}

void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->DecryptFile(inStream, outStream, password);
}

std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) { return pImpl_->CalculateChecksum(inStream); }

}  // namespace CryptoGuard