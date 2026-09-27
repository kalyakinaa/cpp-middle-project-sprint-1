#include "cmd_options.h"
#include "crypto_guard_ctx.h"

#include <fstream>
#include <iostream>
#include <print>
#include <stdexcept>

int main(int argc, char *argv[]) {
    try {
        CryptoGuard::ProgramOptions options;
        options.Parse(argc, argv);

        if (options.IsHelpRequested()) {
            return 0;
        }

        CryptoGuard::CryptoGuardCtx cryptoCtx;
        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;

        std::fstream inFile(options.GetInputFile(), std::ios::in | std::ios::binary);
        if (!inFile.is_open()) {
            throw std::runtime_error("Failed to open input file: " + options.GetInputFile());
        }

        switch (options.GetCommand()) {
        case COMMAND_TYPE::ENCRYPT: {
            std::fstream outFile(options.GetOutputFile(), std::ios::out | std::ios::binary | std::ios::trunc);
            if (!outFile.is_open()) {
                throw std::runtime_error("Failed to open output file: " + options.GetOutputFile());
            }
            cryptoCtx.EncryptFile(inFile, outFile, options.GetPassword());
            std::print("File encoded successfully\n");
            break;
        }

        case COMMAND_TYPE::DECRYPT: {
            std::fstream outFile(options.GetOutputFile(), std::ios::out | std::ios::binary | std::ios::trunc);
            if (!outFile.is_open()) {
                throw std::runtime_error("Failed to open output file: " + options.GetOutputFile());
            }
            cryptoCtx.DecryptFile(inFile, outFile, options.GetPassword());
            std::print("File decoded successfully\n");
            break;
        }

        case COMMAND_TYPE::CHECKSUM:
            std::print("Checksum: {}\n", cryptoCtx.CalculateChecksum(inFile));
            break;

        default:
            throw std::runtime_error("Unsupported command");
        }

    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }

    return 0;
}