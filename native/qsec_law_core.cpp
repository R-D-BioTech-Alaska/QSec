#include <algorithm>
#include <array>
#include <cmath>
#include <complex>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

constexpr const char* REQUEST_MAGIC = "QSEC-QH/1";
constexpr const char* WITNESS_MAGIC = "QSEC-QW/1";
constexpr int MAX_QUBITS = 12;
constexpr int MAX_GATES = 4096;
constexpr long long SCALE = 10000000000LL;
constexpr long long MAX_ANGLE_NANORADIANS = 25132741229LL;

class Sha256 {
public:
    Sha256() { reset(); }

    void update(const unsigned char* data, std::size_t length) {
        for (std::size_t i = 0; i < length; ++i) {
            buffer_[buffer_length_++] = data[i];
            if (buffer_length_ == 64) {
                transform(buffer_.data());
                bit_length_ += 512;
                buffer_length_ = 0;
            }
        }
    }

    void update(const std::string& text) {
        update(reinterpret_cast<const unsigned char*>(text.data()), text.size());
    }

    std::array<unsigned char, 32> final() {
        std::array<unsigned char, 32> digest{};
        std::size_t i = buffer_length_;
        buffer_[i++] = 0x80;
        if (i > 56) {
            while (i < 64) buffer_[i++] = 0;
            transform(buffer_.data());
            i = 0;
        }
        while (i < 56) buffer_[i++] = 0;
        bit_length_ += static_cast<std::uint64_t>(buffer_length_) * 8;
        for (int shift = 56; shift >= 0; shift -= 8) {
            buffer_[i++] = static_cast<unsigned char>((bit_length_ >> shift) & 0xffu);
        }
        transform(buffer_.data());
        for (std::size_t word = 0; word < 8; ++word) {
            digest[word * 4] = static_cast<unsigned char>((state_[word] >> 24) & 0xffu);
            digest[word * 4 + 1] = static_cast<unsigned char>((state_[word] >> 16) & 0xffu);
            digest[word * 4 + 2] = static_cast<unsigned char>((state_[word] >> 8) & 0xffu);
            digest[word * 4 + 3] = static_cast<unsigned char>(state_[word] & 0xffu);
        }
        return digest;
    }

private:
    std::array<unsigned char, 64> buffer_{};
    std::array<std::uint32_t, 8> state_{};
    std::uint64_t bit_length_ = 0;
    std::size_t buffer_length_ = 0;

    static constexpr std::array<std::uint32_t, 64> K = {
        0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
        0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
        0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
        0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
        0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
        0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
        0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
        0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
    };

    static std::uint32_t rotr(std::uint32_t value, unsigned shift) {
        return (value >> shift) | (value << (32u - shift));
    }

    void reset() {
        state_ = {0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
                  0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u};
        bit_length_ = 0;
        buffer_length_ = 0;
        buffer_.fill(0);
    }

    void transform(const unsigned char* block) {
        std::array<std::uint32_t, 64> words{};
        for (std::size_t i = 0; i < 16; ++i) {
            const std::size_t j = i * 4;
            words[i] = (static_cast<std::uint32_t>(block[j]) << 24) |
                       (static_cast<std::uint32_t>(block[j + 1]) << 16) |
                       (static_cast<std::uint32_t>(block[j + 2]) << 8) |
                       static_cast<std::uint32_t>(block[j + 3]);
        }
        for (std::size_t i = 16; i < 64; ++i) {
            const std::uint32_t s0 = rotr(words[i - 15], 7) ^ rotr(words[i - 15], 18) ^ (words[i - 15] >> 3);
            const std::uint32_t s1 = rotr(words[i - 2], 17) ^ rotr(words[i - 2], 19) ^ (words[i - 2] >> 10);
            words[i] = words[i - 16] + s0 + words[i - 7] + s1;
        }
        std::uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
        std::uint32_t e = state_[4], f = state_[5], g = state_[6], h = state_[7];
        for (std::size_t i = 0; i < 64; ++i) {
            const std::uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            const std::uint32_t choose = (e & f) ^ ((~e) & g);
            const std::uint32_t temp1 = h + s1 + choose + K[i] + words[i];
            const std::uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
            const std::uint32_t temp2 = s0 + majority;
            h = g; g = f; f = e; e = d + temp1;
            d = c; c = b; b = a; a = temp1 + temp2;
        }
        state_[0] += a; state_[1] += b; state_[2] += c; state_[3] += d;
        state_[4] += e; state_[5] += f; state_[6] += g; state_[7] += h;
    }
};

std::string sha256(const std::string& value) {
    Sha256 hash;
    hash.update(value);
    const auto digest = hash.final();
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (unsigned char byte : digest) output << std::setw(2) << static_cast<unsigned>(byte);
    return output.str();
}

bool is_hex64(const std::string& value, bool allow_dash = false) {
    if (allow_dash && value == "-") return true;
    if (value.size() != 64) return false;
    return std::all_of(value.begin(), value.end(), [](char ch) {
        return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
    });
}

long long parse_integer(const std::string& value, const char* field) {
    if (value.empty()) throw std::runtime_error(std::string(field) + " is empty");
    std::size_t consumed = 0;
    long long result = 0;
    try {
        result = std::stoll(value, &consumed, 10);
    } catch (const std::exception&) {
        throw std::runtime_error(std::string(field) + " is not an integer");
    }
    if (consumed != value.size() || std::to_string(result) != value) {
        throw std::runtime_error(std::string(field) + " is not canonical");
    }
    return result;
}

int parse_int_range(const std::string& value, const char* field, int minimum, int maximum) {
    const long long parsed = parse_integer(value, field);
    if (parsed < minimum || parsed > maximum) {
        throw std::runtime_error(std::string(field) + " is outside the allowed range");
    }
    return static_cast<int>(parsed);
}

long long quantize(double value) {
    const double scaled = value * static_cast<double>(SCALE);
    if (!std::isfinite(scaled) || scaled > static_cast<double>(std::numeric_limits<long long>::max()) ||
        scaled < static_cast<double>(std::numeric_limits<long long>::min())) {
        throw std::runtime_error("non-finite quantum value");
    }
    return scaled >= 0.0 ? static_cast<long long>(std::floor(scaled + 0.5))
                         : static_cast<long long>(std::ceil(scaled - 0.5));
}

std::vector<std::string> split(const std::string& value, char delimiter) {
    std::vector<std::string> result;
    std::string part;
    std::istringstream stream(value);
    while (std::getline(stream, part, delimiter)) result.push_back(part);
    if (!value.empty() && value.back() == delimiter) result.emplace_back();
    return result;
}

struct Gate {
    std::string name;
    int first;
    int second;
    long long angle_nanoradians;
};

struct Request {
    std::string raw;
    std::string request_id;
    std::string nonce;
    std::string policy_digest;
    std::string parent_digest;
    int qubits;
    int initial_basis;
    std::vector<Gate> gates;
};

std::string field_value(const std::string& line, const std::string& key) {
    const std::string prefix = key + "=";
    if (line.rfind(prefix, 0) != 0) throw std::runtime_error("expected " + key);
    return line.substr(prefix.size());
}

Request parse_request(const std::string& raw) {
    if (raw.empty() || raw.back() != '\n') throw std::runtime_error("request must end with newline");
    std::vector<std::string> lines;
    std::string line;
    std::istringstream stream(raw);
    while (std::getline(stream, line)) lines.push_back(line);
    if (lines.size() < 9 || lines.front() != REQUEST_MAGIC || lines.back() != "END") {
        throw std::runtime_error("invalid request framing");
    }
    Request request{};
    request.raw = raw;
    request.request_id = field_value(lines[1], "request_id");
    request.nonce = field_value(lines[2], "nonce");
    request.policy_digest = field_value(lines[3], "policy_digest");
    request.parent_digest = field_value(lines[4], "parent_digest");
    request.qubits = parse_int_range(field_value(lines[5], "qubits"), "qubits", 1, MAX_QUBITS);
    request.initial_basis = parse_int_range(
        field_value(lines[6], "initial_basis"), "initial_basis", 0, (1 << request.qubits) - 1
    );
    const int gate_count = parse_int_range(field_value(lines[7], "gate_count"), "gate_count", 0, MAX_GATES);
    if (!is_hex64(request.request_id) || !is_hex64(request.nonce) ||
        !is_hex64(request.policy_digest, true) || !is_hex64(request.parent_digest, true)) {
        throw std::runtime_error("invalid digest field");
    }
    if (lines.size() != static_cast<std::size_t>(gate_count + 9)) {
        throw std::runtime_error("gate count mismatch");
    }
    for (int i = 0; i < gate_count; ++i) {
        const std::string body = field_value(lines[8 + i], "gate");
        const auto fields = split(body, ',');
        if (fields.size() != 4) throw std::runtime_error("invalid gate record");
        Gate gate{fields[0],
                  parse_int_range(fields[1], "first", 0, request.qubits - 1),
                  parse_int_range(fields[2], "second", -1, request.qubits - 1),
                  parse_integer(fields[3], "angle")};
        const bool one = gate.name == "X" || gate.name == "Y" || gate.name == "Z" || gate.name == "H" ||
                         gate.name == "S" || gate.name == "T" || gate.name == "RX" || gate.name == "RY" || gate.name == "RZ";
        const bool two = gate.name == "CNOT" || gate.name == "CZ" || gate.name == "SWAP";
        const bool rotation = gate.name == "RX" || gate.name == "RY" || gate.name == "RZ";
        if (!one && !two) throw std::runtime_error("unsupported gate");
        if (gate.first < 0 || gate.first >= request.qubits) throw std::runtime_error("gate target outside register");
        if (one && (gate.second != -1 || (!rotation && gate.angle_nanoradians != 0))) {
            throw std::runtime_error("invalid one-qubit gate arguments");
        }
        if (rotation && (gate.angle_nanoradians < -MAX_ANGLE_NANORADIANS ||
                         gate.angle_nanoradians > MAX_ANGLE_NANORADIANS)) {
            throw std::runtime_error("rotation angle exceeds the cross-code bound");
        }
        if (two && (gate.second < 0 || gate.second >= request.qubits || gate.second == gate.first || gate.angle_nanoradians != 0)) {
            throw std::runtime_error("invalid two-qubit gate arguments");
        }
        request.gates.push_back(gate);
    }
    return request;
}

void apply_one(std::vector<std::complex<double>>& state, int qubit,
               std::complex<double> a, std::complex<double> b,
               std::complex<double> c, std::complex<double> d) {
    const std::size_t step = static_cast<std::size_t>(1) << qubit;
    const std::size_t span = step << 1;
    for (std::size_t base = 0; base < state.size(); base += span) {
        for (std::size_t offset = 0; offset < step; ++offset) {
            const std::size_t low = base + offset;
            const std::size_t high = low + step;
            const auto x = state[low];
            const auto y = state[high];
            state[low] = a * x + b * y;
            state[high] = c * x + d * y;
        }
    }
}

void apply_gate(std::vector<std::complex<double>>& state, const Gate& gate) {
    const std::complex<double> I(0.0, 1.0);
    if (gate.name == "X") apply_one(state, gate.first, 0.0, 1.0, 1.0, 0.0);
    else if (gate.name == "Y") apply_one(state, gate.first, 0.0, -I, I, 0.0);
    else if (gate.name == "Z") apply_one(state, gate.first, 1.0, 0.0, 0.0, -1.0);
    else if (gate.name == "H") {
        const double k = 1.0 / std::sqrt(2.0);
        apply_one(state, gate.first, k, k, k, -k);
    } else if (gate.name == "S") apply_one(state, gate.first, 1.0, 0.0, 0.0, I);
    else if (gate.name == "T") {
        const double pi = std::acos(-1.0);
        const std::complex<double> phase(std::cos(pi / 4.0), std::sin(pi / 4.0));
        apply_one(state, gate.first, 1.0, 0.0, 0.0, phase);
    } else if (gate.name == "RX" || gate.name == "RY" || gate.name == "RZ") {
        const double half = static_cast<double>(gate.angle_nanoradians) * 1e-9 / 2.0;
        const double cosine = std::cos(half);
        const double sine = std::sin(half);
        if (gate.name == "RX") apply_one(state, gate.first, cosine, -I * sine, -I * sine, cosine);
        else if (gate.name == "RY") apply_one(state, gate.first, cosine, -sine, sine, cosine);
        else {
            const std::complex<double> low(std::cos(-half), std::sin(-half));
            const std::complex<double> high(std::cos(half), std::sin(half));
            apply_one(state, gate.first, low, 0.0, 0.0, high);
        }
    } else if (gate.name == "CNOT") {
        const std::size_t control = static_cast<std::size_t>(1) << gate.first;
        const std::size_t target = static_cast<std::size_t>(1) << gate.second;
        for (std::size_t index = 0; index < state.size(); ++index) {
            if ((index & control) && !(index & target)) std::swap(state[index], state[index | target]);
        }
    } else if (gate.name == "CZ") {
        const std::size_t control = static_cast<std::size_t>(1) << gate.first;
        const std::size_t target = static_cast<std::size_t>(1) << gate.second;
        for (std::size_t index = 0; index < state.size(); ++index) {
            if ((index & control) && (index & target)) state[index] = -state[index];
        }
    } else if (gate.name == "SWAP") {
        const std::size_t first = static_cast<std::size_t>(1) << gate.first;
        const std::size_t second = static_cast<std::size_t>(1) << gate.second;
        for (std::size_t index = 0; index < state.size(); ++index) {
            if ((index & first) && !(index & second)) std::swap(state[index], state[(index ^ first) | second]);
        }
    }
}

std::string join(const std::vector<std::string>& values, const char* delimiter) {
    std::ostringstream output;
    for (std::size_t i = 0; i < values.size(); ++i) {
        if (i) output << delimiter;
        output << values[i];
    }
    return output.str();
}

std::string execute(const Request& request) {
    std::vector<std::complex<double>> state(static_cast<std::size_t>(1) << request.qubits, {0.0, 0.0});
    state[static_cast<std::size_t>(request.initial_basis)] = {1.0, 0.0};
    for (const auto& gate : request.gates) apply_gate(state, gate);

    std::complex<double> phase_anchor(1.0, 0.0);
    for (const auto& amplitude : state) {
        if (std::abs(amplitude) > 1e-15) {
            phase_anchor = amplitude;
            break;
        }
    }
    const std::complex<double> phase = std::conj(phase_anchor) / std::abs(phase_anchor);
    std::vector<std::string> amplitude_records;
    std::vector<std::string> probability_records;
    amplitude_records.reserve(state.size());
    probability_records.reserve(state.size());
    double norm = 0.0;
    for (const auto& amplitude : state) {
        const std::complex<double> canonical = amplitude * phase;
        amplitude_records.push_back(std::to_string(quantize(canonical.real())) + "," + std::to_string(quantize(canonical.imag())));
        const double probability = amplitude.real() * amplitude.real() + amplitude.imag() * amplitude.imag();
        probability_records.push_back(std::to_string(quantize(probability)));
        norm += probability;
    }
    const std::string request_digest = sha256(request.raw);
    const std::string state_digest = sha256(join(amplitude_records, ";"));
    const std::string probability_digest = sha256(join(probability_records, ","));
    const long long norm_scaled = quantize(norm);
    const std::string consensus = sha256(request_digest + "|" + state_digest + "|" + probability_digest + "|" +
                                         std::to_string(norm_scaled) + "|" + std::to_string(request.qubits));
    std::ostringstream output;
    output << WITNESS_MAGIC << '\n'
           << "request_digest=" << request_digest << '\n'
           << "backend_id=native-cpp" << '\n'
           << "state_digest=" << state_digest << '\n'
           << "probability_digest=" << probability_digest << '\n'
           << "norm_scaled=" << norm_scaled << '\n'
           << "consensus_digest=" << consensus << '\n'
           << "END\n";
    return output.str();
}

}  // namespace

int main() {
    try {
        std::ostringstream input;
        input << std::cin.rdbuf();
        const Request request = parse_request(input.str());
        std::cout << execute(request);
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "QSEC-QE/1\nerror=NativeCoreError:" << error.what() << "\nEND\n";
        return 2;
    }
}
