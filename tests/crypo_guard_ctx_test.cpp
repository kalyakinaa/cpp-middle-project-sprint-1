#include "crypto_guard_ctx.h"

#include <gtest/gtest.h>

#include <sstream>
#include <string>

namespace {

constexpr std::string_view TEST_PASSWORD = "test_pass_123";

}  // namespace

TEST(CryptoGuardCtx, EncryptProducesDifferentOutput) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream in("Hello, World!");
    std::stringstream out;

    ASSERT_NO_THROW(ctx.EncryptFile(in, out, TEST_PASSWORD));

    std::string encrypted = out.str();

    EXPECT_FALSE(encrypted.empty());
    EXPECT_NE(encrypted, "Hello, World!");
}

TEST(CryptoGuardCtx, EncryptDecryptRoundTrip) {
    CryptoGuard::CryptoGuardCtx ctx;
    const std::string original = "Hello, World!";
    std::stringstream in(original);
    std::stringstream encryptedStream;

    ASSERT_NO_THROW(ctx.EncryptFile(in, encryptedStream, TEST_PASSWORD));

    std::stringstream decryptedStream;
    ASSERT_NO_THROW(ctx.DecryptFile(encryptedStream, decryptedStream, TEST_PASSWORD));

    EXPECT_EQ(decryptedStream.str(), original);
}

TEST(CryptoGuardCtx, EncryptEmptyStream) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream in("");
    std::stringstream out;

    ASSERT_NO_THROW(ctx.EncryptFile(in, out, TEST_PASSWORD));
    EXPECT_FALSE(out.str().empty());
}

TEST(CryptoGuardCtx, EncryptThrowsOnBadInputStream) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream in;
    in.setstate(std::ios::badbit);
    std::stringstream out;

    ASSERT_THROW(ctx.EncryptFile(in, out, TEST_PASSWORD), std::runtime_error);
}

TEST(CryptoGuardCtx, DecryptThrowsOnBadOutputStream) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream in("Hello");
    std::stringstream out;
    out.setstate(std::ios::badbit);

    ASSERT_THROW(ctx.DecryptFile(in, out, TEST_PASSWORD), std::runtime_error);
}

TEST(CryptoGuardCtx, DecryptThrowsOnInvalidData) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream in("Hello, World!");
    std::stringstream out;

    ASSERT_THROW(ctx.DecryptFile(in, out, TEST_PASSWORD), std::runtime_error);
}

TEST(CryptoGuardCtx, ChecksumKnownValue) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream in("");
    std::string expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    EXPECT_EQ(ctx.CalculateChecksum(in), expected);
}

TEST(CryptoGuardCtx, ChecksumMatchesForSameData) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream in1("Hello, World!");
    std::stringstream in2("Hello, World!");

    EXPECT_EQ(ctx.CalculateChecksum(in1), ctx.CalculateChecksum(in2));
}

TEST(CryptoGuardCtx, ChecksumDiffersForDifferentData) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream in1("Hello, ");
    std::stringstream in2("World!");

    EXPECT_NE(ctx.CalculateChecksum(in1), ctx.CalculateChecksum(in2));
}

TEST(CryptoGuardCtx, ChecksumThrowsOnBadStream) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream in;
    in.setstate(std::ios::badbit);

    ASSERT_THROW(ctx.CalculateChecksum(in), std::runtime_error);
}

TEST(CryptoGuardCtx, ChecksumStableBeforeAndAfterEncryptDecrypt) {
    CryptoGuard::CryptoGuardCtx ctx;
    const std::string original = "Hello, World!";

    std::stringstream in1(original);
    std::string checksumBefore = ctx.CalculateChecksum(in1);

    std::stringstream in2(original);
    std::stringstream encrypted;
    ctx.EncryptFile(in2, encrypted, TEST_PASSWORD);

    std::stringstream decrypted;
    ctx.DecryptFile(encrypted, decrypted, TEST_PASSWORD);

    std::string checksumAfter = ctx.CalculateChecksum(decrypted);

    EXPECT_EQ(checksumBefore, checksumAfter);
}