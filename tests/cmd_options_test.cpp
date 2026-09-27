#include "cmd_options.h"

#include <gtest/gtest.h>

#include <string>
#include <vector>

namespace {

std::vector<char *> MakeArgv(std::vector<std::string> &args) {
    std::vector<char *> argv;
    argv.reserve(args.size());
    for (auto &a : args) {
        argv.push_back(a.data());
    }
    return argv;
}

}  // namespace

TEST(ProgramOptions, ParsesEncryptCommand) {
    std::vector<std::string> args = {"test",     "--command",    "encrypt",    "--input", "file.txt",
                                     "--output", "file.txt.enc", "--password", "password"};
    auto argv = MakeArgv(args);
    CryptoGuard::ProgramOptions opts;
    ASSERT_NO_THROW(opts.Parse(static_cast<int>(argv.size()), argv.data()));
    EXPECT_EQ(opts.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(opts.GetInputFile(), "file.txt");
    EXPECT_EQ(opts.GetOutputFile(), "file.txt.enc");
    EXPECT_EQ(opts.GetPassword(), "password");
}

TEST(ProgramOptions, ParsesDecryptCommand) {
    std::vector<std::string> args = {"test",     "--command", "decrypt",    "--input", "file.txt.enc",
                                     "--output", "file.txt",  "--password", "password"};
    auto argv = MakeArgv(args);
    CryptoGuard::ProgramOptions opts;
    ASSERT_NO_THROW(opts.Parse(static_cast<int>(argv.size()), argv.data()));
    EXPECT_EQ(opts.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::DECRYPT);
    EXPECT_EQ(opts.GetInputFile(), "file.txt.enc");
    EXPECT_EQ(opts.GetOutputFile(), "file.txt");
    EXPECT_EQ(opts.GetPassword(), "password");
}

TEST(ProgramOptions, ParsesChecksumCommand) {
    std::vector<std::string> args = {"test", "--command", "checksum", "--input", "file.txt"};
    auto argv = MakeArgv(args);
    CryptoGuard::ProgramOptions opts;
    ASSERT_NO_THROW(opts.Parse(static_cast<int>(argv.size()), argv.data()));
    EXPECT_EQ(opts.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::CHECKSUM);
    EXPECT_EQ(opts.GetInputFile(), "file.txt");
}

TEST(ProgramOptions, ShortOptions) {
    std::vector<std::string> args = {"test", "-c", "encrypt", "-i", "file.txt", "-o", "file.txt.enc", "-p", "pw"};
    auto argv = MakeArgv(args);
    CryptoGuard::ProgramOptions opts;
    ASSERT_NO_THROW(opts.Parse(static_cast<int>(argv.size()), argv.data()));
    EXPECT_EQ(opts.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(opts.GetInputFile(), "file.txt");
    EXPECT_EQ(opts.GetOutputFile(), "file.txt.enc");
    EXPECT_EQ(opts.GetPassword(), "pw");
}

TEST(ProgramOptions, ThrowsOnUnknownCommand) {
    std::vector<std::string> args = {"test", "--command", "unknown", "--input", "file.txt"};
    auto argv = MakeArgv(args);
    CryptoGuard::ProgramOptions opts;
    EXPECT_THROW(opts.Parse(static_cast<int>(argv.size()), argv.data()), std::runtime_error);
}

TEST(ProgramOptions, ThrowsOnMissingCommand) {
    std::vector<std::string> args = {"test", "--input", "file.txt"};
    auto argv = MakeArgv(args);
    CryptoGuard::ProgramOptions opts;
    EXPECT_THROW(opts.Parse(static_cast<int>(argv.size()), argv.data()), std::runtime_error);
}

TEST(ProgramOptions, ThrowsOnMissingInput) {
    std::vector<std::string> args = {"test", "--command", "encrypt", "--password", "pw"};
    auto argv = MakeArgv(args);
    CryptoGuard::ProgramOptions opts;
    EXPECT_THROW(opts.Parse(static_cast<int>(argv.size()), argv.data()), std::runtime_error);
}

TEST(ProgramOptions, ThrowsOnMissingPasswordForEncrypt) {
    std::vector<std::string> args = {"test", "--command", "encrypt", "--input", "file.txt"};
    auto argv = MakeArgv(args);
    CryptoGuard::ProgramOptions opts;
    EXPECT_THROW(opts.Parse(static_cast<int>(argv.size()), argv.data()), std::runtime_error);
}

TEST(ProgramOptions, HelpDoesNotThrow) {
    std::vector<std::string> args = {"test", "--help"};
    auto argv = MakeArgv(args);
    CryptoGuard::ProgramOptions opts;
    ASSERT_NO_THROW(opts.Parse(static_cast<int>(argv.size()), argv.data()));
}

TEST(ProgramOptions, ThrowsOnUnknownOption) {
    std::vector<std::string> args = {"test", "--unknown", "value"};
    auto argv = MakeArgv(args);
    CryptoGuard::ProgramOptions opts;
    EXPECT_THROW(opts.Parse(static_cast<int>(argv.size()), argv.data()), std::runtime_error);
}