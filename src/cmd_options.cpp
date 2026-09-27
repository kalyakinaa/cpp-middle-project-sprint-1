#include "cmd_options.h"

#include <iostream>

namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    desc_.add_options()("help,h", "Show available options")("command,c", boost::program_options::value<std::string>(),
                                                            "Command: encrypt, decrypt or checksum")(
        "input,i", boost::program_options::value<std::string>(),
        "Path to input file")("output,o", boost::program_options::value<std::string>(), "Path to output file")(
        "password,p", boost::program_options::value<std::string>(), "Password for encryption/decryption");
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {
    boost::program_options::variables_map vm;

    try {
        boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc_), vm);
        boost::program_options::notify(vm);
    } catch (const boost::program_options::error &e) {
        throw std::runtime_error(std::string("Command line parsing error: ") + e.what());
    }

    if (vm.count("help")) {
        std::cout << desc_ << std::endl;
        helpRequested_ = true;
        return;
    }

    if (!vm.count("command")) {
        throw std::runtime_error("Command is required. Use --help for more information.");
    }

    std::string commandStr = vm["command"].as<std::string>();
    auto it = commandMapping_.find(commandStr);
    if (it == commandMapping_.end()) {
        throw std::runtime_error("Unknown command: " + commandStr + ". Available: encrypt, decrypt, checksum");
    }
    command_ = it->second;

    if (!vm.count("input")) {
        throw std::runtime_error("Input file is required. Use --help for more information.");
    }
    inputFile_ = vm["input"].as<std::string>();

    if (vm.count("output")) {
        outputFile_ = vm["output"].as<std::string>();
    }

    if (command_ == COMMAND_TYPE::ENCRYPT || command_ == COMMAND_TYPE::DECRYPT) {
        if (!vm.count("password")) {
            throw std::runtime_error("Password is required for encrypt/decrypt. Use --help for more information.");
        }
        password_ = vm["password"].as<std::string>();
    }
}

}  // namespace CryptoGuard