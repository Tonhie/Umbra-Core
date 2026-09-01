#include "certificate/certificate_authority.h"
#include "certificate/certificate_library.h"
#include "certificate/trusted_authority.h"
#include "crypto/crypto_engine.h"
#include "hash/sha_256.h"
#include "mail/secure_mail.h"
#include "pki/pki_user.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <exception>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <iterator>
#include <map>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace {

using umbra::certificate::Certificate;
using umbra::crypto::CryptoType;
using umbra::certificate::CertificateAuthority;
using umbra::certificate::CertificateLibrary;
using umbra::certificate::CertificatePath;
using umbra::certificate::KeyPurpose;
using umbra::certificate::TrustedAuthority;
using umbra::pki::PkiUser;

// Elgamal key size used by the demo (in bits). The default of the library
// is 2048 bits, whose key generation takes about 90 seconds; the demo uses
// 512 bits so that it finishes quickly while keeping the same algorithms.
const long kDemoElgamalBits = 512;

const std::string kSampleMail =
    "Hello Bob!\n"
    "This is Alice. Here is the secret plan for our course design:\n"
    "  1. RSA + Elgamal encryption and signature\n"
    "  2. Simple certificate scheme\n"
    "  3. Simple PKI system\n"
    "  4. Simple secure mail system\n"
    "Best regards, Alice.\n";

std::string read_file(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("failed to open input file: " + path.string());
    }
    return std::string(
        std::istreambuf_iterator<char>(file),
        std::istreambuf_iterator<char>()
    );
}

void write_file(const std::filesystem::path& path, const std::string& content) {
    std::ofstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("failed to open output file: " + path.string());
    }
    file.write(content.data(), static_cast<std::streamsize>(content.size()));
}

void print_section(const std::string& title) {
    std::cout << "\n============================================================\n"
              << title << "\n"
              << "============================================================\n";
}

std::string purpose_label(KeyPurpose purpose) {
    return (purpose == KeyPurpose::Encryption) ? "enc" : "sig";
}

/*
    任务1 --- RSA 加密和签名
*/

int demo_rsa(
    const std::filesystem::path& input_file,
    const std::filesystem::path& output_dir
) {
    print_section("[任务1] RSA 加密和签名");

    const std::filesystem::path rsa_dir = output_dir / "rsa";
    std::filesystem::create_directories(rsa_dir);

    std::cout << "生成 RSA 密钥对（p, q 均为 1024 比特素数）...\n";
    auto engine = umbra::crypto::create_encryption_engine(
        umbra::crypto::CryptoType::RSA
    );
    auto keypair = engine->generate_keypair(1024);

    const std::string public_key_text = static_cast<std::string>(*keypair.public_key);
    const std::string private_key_text = static_cast<std::string>(*keypair.private_key);
    write_file(rsa_dir / "rsa_public_key.txt", public_key_text);
    write_file(rsa_dir / "rsa_private_key.txt", private_key_text);
    std::cout << "RSA 公钥 (n, e):\n" << public_key_text << "\n";
    std::cout << "RSA 私钥 (p, q, d):\n" << private_key_text << "\n";

    const std::string plaintext =
        input_file.empty() ? kSampleMail : read_file(input_file);
    std::cout << "明文长度: " << plaintext.size() << " 字节\n";
    write_file(rsa_dir / "rsa_plaintext.txt", plaintext);

    const std::string ciphertext = engine->encrypt(plaintext, *keypair.public_key);
    write_file(rsa_dir / "rsa_ciphertext.txt", ciphertext);
    std::cout << "RSA 密文:\n" << ciphertext << "\n";

    const std::string decrypted = engine->decrypt(ciphertext, *keypair.private_key);
    write_file(rsa_dir / "rsa_decrypted.txt", decrypted);
    std::cout << "RSA 解密结果与明文一致: "
              << (decrypted == plaintext ? "是" : "否") << "\n";

    auto signer = umbra::crypto::create_signature_engine(
        umbra::crypto::CryptoType::RSA
    );
    const std::string signature = signer->sign(plaintext, *keypair.private_key);
    write_file(rsa_dir / "rsa_signature.txt", signature);
    const bool verified = signer->verify(plaintext, signature, *keypair.public_key);
    std::cout << "RSA 签名验证（对明文 Hash 签名）: "
              << (verified ? "通过" : "失败") << "\n";
    std::cout << "产物目录: " << rsa_dir.string() << "\n";
    return verified ? 0 : 1;
}

/*
    任务1 --- Elgamal 加密和签名
*/

int demo_elgamal(
    const std::filesystem::path& input_file,
    const std::filesystem::path& output_dir
) {
    print_section("[任务1] Elgamal 加密和签名");

    const std::filesystem::path elgamal_dir = output_dir / "elgamal";
    std::filesystem::create_directories(elgamal_dir);

    std::cout << "生成 Elgamal 密钥对（p = 2q + 1 安全素数, "
              << kDemoElgamalBits << " 比特）...\n";
    auto engine = umbra::crypto::create_encryption_engine(
        umbra::crypto::CryptoType::Elgamal
    );
    auto keypair = engine->generate_keypair(kDemoElgamalBits);

    const std::string public_key_text = static_cast<std::string>(*keypair.public_key);
    const std::string private_key_text = static_cast<std::string>(*keypair.private_key);
    write_file(elgamal_dir / "elgamal_public_key.txt", public_key_text);
    write_file(elgamal_dir / "elgamal_private_key.txt", private_key_text);
    std::cout << "Elgamal 公钥 (p, alpha, beta):\n" << public_key_text << "\n";
    std::cout << "Elgamal 私钥 (p, alpha, a):\n" << private_key_text << "\n";

    const std::string plaintext =
        input_file.empty() ? kSampleMail : read_file(input_file);
    std::cout << "明文长度: " << plaintext.size() << " 字节\n";
    write_file(elgamal_dir / "elgamal_plaintext.txt", plaintext);

    const std::string ciphertext = engine->encrypt(plaintext, *keypair.public_key);
    write_file(elgamal_dir / "elgamal_ciphertext.txt", ciphertext);
    std::cout << "Elgamal 密文（每个分组: 长度-c1-c2）:\n" << ciphertext << "\n";

    const std::string decrypted = engine->decrypt(ciphertext, *keypair.private_key);
    write_file(elgamal_dir / "elgamal_decrypted.txt", decrypted);
    std::cout << "Elgamal 解密结果与明文一致: "
              << (decrypted == plaintext ? "是" : "否") << "\n";

    auto signer = umbra::crypto::create_signature_engine(
        umbra::crypto::CryptoType::Elgamal
    );
    const std::string signature = signer->sign(plaintext, *keypair.private_key);
    write_file(elgamal_dir / "elgamal_signature.txt", signature);
    const bool verified = signer->verify(plaintext, signature, *keypair.public_key);
    std::cout << "Elgamal 签名验证: " << (verified ? "通过" : "失败") << "\n";
    std::cout << "产物目录: " << elgamal_dir.string() << "\n";
    return verified ? 0 : 1;
}

/*
    任务1 --- 简单证书方案
*/

int demo_certificate(const std::filesystem::path& output_dir) {
    print_section("[任务1] 简单证书方案 (TA 签发 Cert(Alice))");

    const std::filesystem::path cert_dir = output_dir / "certificates";
    std::filesystem::create_directories(cert_dir);

    // Alice 的 RSA 公钥，TA 用 RSA 签名算法签发证书 (flag1 = RSA)。
    {
        TrustedAuthority ta("TA", CryptoType::RSA);
        auto alice_engine = umbra::crypto::create_encryption_engine(
            umbra::crypto::CryptoType::RSA
        );
        auto alice_keypair = alice_engine->generate_keypair(1024);
        std::string alice_id = "Alice";
        const std::string ver_alice = umbra::certificate::public_key_to_string(
            *alice_keypair.public_key
        );
        const Certificate cert = ta.grant_certificate(
            alice_id, ver_alice, KeyPurpose::Encryption
        );
        const std::string cert_text = cert.to_string();
        write_file(cert_dir / "alice_rsa.cert", cert_text);
        std::cout << "TA(RSA) 为 Alice 颁发的证书 (flag1=RSA, flag2=Encryption):\n"
                  << cert_text << "\n";
        const bool ok = umbra::certificate::verify_certificate_signature(
            cert, ta.public_key()
        );
        std::cout << "证书签名验证: " << (ok ? "通过" : "失败") << "\n";

        // txt 证书文件的重新解析。
        const Certificate parsed = Certificate::from_string(cert_text);
        std::cout << "txt 证书文件重新解析: "
                  << (parsed.Subject() == "Alice" ? "成功" : "失败") << "\n";
    }

    // Alice 的 Elgamal 公钥，TA 用 Elgamal 签名算法签发证书 (flag1 = Elgamal)。
    {
        TrustedAuthority ta("TA", CryptoType::Elgamal, kDemoElgamalBits);
        auto alice_engine = umbra::crypto::create_encryption_engine(
            umbra::crypto::CryptoType::Elgamal
        );
        auto alice_keypair = alice_engine->generate_keypair(kDemoElgamalBits);
        std::string alice_id = "Alice";
        const std::string ver_alice = umbra::certificate::public_key_to_string(
            *alice_keypair.public_key
        );
        const Certificate cert = ta.grant_certificate(
            alice_id, ver_alice, KeyPurpose::Signature
        );
        const std::string cert_text = cert.to_string();
        write_file(cert_dir / "alice_elgamal.cert", cert_text);
        std::cout << "TA(Elgamal) 为 Alice 颁发的证书 (flag1=Elgamal, flag2=Signature):\n"
                  << cert_text << "\n";
        const bool ok = umbra::certificate::verify_certificate_signature(
            cert, ta.public_key()
        );
        std::cout << "证书签名验证: " << (ok ? "通过" : "失败") << "\n";
    }

    std::cout << "产物目录: " << cert_dir.string() << "\n";
    return 0;
}

/*
    任务4 --- 简易 PKI 系统（严格层次） + 任务5 --- 简易安全邮件系统
*/

int demo_pki_and_mail(
    const std::filesystem::path& input_file,
    const std::filesystem::path& output_dir
) {
    print_section("[任务4] 简易 PKI 系统（严格层次结构）");

    const std::filesystem::path pki_dir = output_dir / "pki";
    const std::filesystem::path mail_dir = output_dir / "mail";
    std::filesystem::create_directories(pki_dir);
    std::filesystem::create_directories(mail_dir);

    // 1. 建立层次: CA_root -> CA1, CA2 -> 用户
    std::cout << "创建根 CA (CA_root) 并生成自签名证书...\n";
    CertificateAuthority ca_root("CA_root", CryptoType::RSA);
    const Certificate root_cert = ca_root.self_sign();
    write_file(pki_dir / "root.cert", root_cert.to_string());

    std::cout << "创建下级 CA (CA1, CA2)，证书由 CA_root 签发...\n";
    CertificateAuthority ca1("CA1", CryptoType::Elgamal, kDemoElgamalBits);
    CertificateAuthority ca2("CA2", CryptoType::RSA);
    const Certificate ca1_cert = ca_root.issue_certificate(
        "CA1", ca1.public_key_text(), KeyPurpose::Signature
    );
    const Certificate ca2_cert = ca_root.issue_certificate(
        "CA2", ca2.public_key_text(), KeyPurpose::Signature
    );
    write_file(pki_dir / "ca1.cert", ca1_cert.to_string());
    write_file(pki_dir / "ca2.cert", ca2_cert.to_string());

    // 2. 证书库：只存储由 CA 颁发且验证通过的证书。
    std::cout << "初始化证书库并存储各 CA 的证书...\n";
    CertificateLibrary library("CA_root", ca_root.public_key());
    if (!library.store(root_cert)) {
        std::cerr << "证书库拒绝根证书\n";
        return 1;
    }
    if (!library.store(ca1_cert) || !library.store(ca2_cert)) {
        std::cerr << "证书库拒绝 CA 证书\n";
        return 1;
    }

    // 3. 用户向 CA 申请证书。
    std::cout << "用户申请证书: Alice -> CA1, Bob -> CA2, Eve -> CA1\n";
    PkiUser alice("Alice", CryptoType::RSA, CryptoType::RSA);
    PkiUser bob("Bob", CryptoType::Elgamal, CryptoType::RSA,
                kDemoElgamalBits);
    PkiUser eve("Eve", CryptoType::RSA, CryptoType::Elgamal,
                kDemoElgamalBits);
    alice.apply_for_certificates(ca1);
    bob.apply_for_certificates(ca2);
    eve.apply_for_certificates(ca1);
    for (const auto& cert : alice.certificates()) {
        if (!library.store(cert)) {
            std::cerr << "证书库拒绝 Alice 的证书\n";
            return 1;
        }
        write_file(
            pki_dir / ("alice_" + purpose_label(cert.Purpose()) + ".cert"),
            cert.to_string()
        );
    }
    for (const auto& cert : bob.certificates()) {
        if (!library.store(cert)) {
            std::cerr << "证书库拒绝 Bob 的证书\n";
            return 1;
        }
        write_file(
            pki_dir / ("bob_" + purpose_label(cert.Purpose()) + ".cert"),
            cert.to_string()
        );
    }
    for (const auto& cert : eve.certificates()) {
        if (!library.store(cert)) {
            std::cerr << "证书库拒绝 Eve 的证书\n";
            return 1;
        }
        write_file(
            pki_dir / ("eve_" + purpose_label(cert.Purpose()) + ".cert"),
            cert.to_string()
        );
    }
    std::cout << "证书库中证书总数: " << library.size() << "\n";

    // 4. 证书查询与证书路径（证书链）验证。
    std::cout << "\n使用例子: Bob 在证书库中查询 Alice 的证书路径...\n";
    const CertificatePath alice_path = library.query("Alice");
    std::cout << "Alice 的证书路径 (证书链):\n";
    for (const auto& cert : alice_path.certificates) {
        std::cout << "  - " << cert.Subject() << " (签发者: " << cert.Issuer()
                  << ", flag1=" << static_cast<int>(cert.Algorithm())
                  << " [0=RSA,1=Elgamal], flag2="
                  << static_cast<int>(cert.Purpose())
                  << " [0=加密,1=签名])\n";
    }
    std::string alice_chain_text;
    for (const auto& cert : alice_path.certificates) {
        alice_chain_text += cert.to_string();
        alice_chain_text += "\n";
    }
    write_file(pki_dir / "alice_chain.txt", alice_chain_text);
    const bool alice_chain_ok = umbra::certificate::verify_certificate_path(
        alice_path, ca_root.public_key()
    );
    std::cout << "证书路径验证: " << (alice_chain_ok ? "通过" : "失败") << "\n";

    // 5. 使用例子: Alice 发送消息和签名, Bob 验证。
    const std::string message =
        "Bob, please review the design document by Friday. -- Alice";
    const std::string alice_signature = alice.sign(message);
    write_file(pki_dir / "alice_message.txt", message);
    write_file(pki_dir / "alice_signature.txt", alice_signature);
    std::cout << "\nAlice 发送消息: " << message << "\n";
    std::cout << "Alice 的签名:\n" << alice_signature << "\n";

    auto alice_public_key = umbra::certificate::parse_public_key(
        alice_path.certificates.back().SubjectPublicKey()
    );
    auto signer = umbra::crypto::create_signature_engine(
        alice_public_key->type()
    );
    const bool signature_ok = signer->verify(message, alice_signature, *alice_public_key);
    std::cout << "Bob 用 Alice 证书中的公钥验证签名: "
              << (signature_ok ? "通过" : "失败") << "\n";

    /*
        任务5 --- 简易安全邮件系统
    */

    print_section("[任务5] 简易安全邮件系统（无网络传输）");

    const std::string mail_content =
        input_file.empty() ? kSampleMail : read_file(input_file);
    std::cout << "邮件内容 m (" << mail_content.size() << " 字节):\n"
              << mail_content << "\n";
    write_file(mail_dir / "mail_plaintext.txt", mail_content);

    std::cout << "\n[发送端 Alice]\n"
              << "  步骤1: 在证书库中查询 Bob 的加密公钥证书链并验证...\n";
    const CertificatePath bob_path = library.query("Bob", KeyPurpose::Encryption);
    std::cout << "  Bob 的加密证书路径:\n";
    for (const auto& cert : bob_path.certificates) {
        std::cout << "    - " << cert.Subject() << "\n";
    }
    const bool bob_chain_ok = umbra::certificate::verify_certificate_path(
        bob_path, ca_root.public_key()
    );
    std::cout << "  证书链验证: " << (bob_chain_ok ? "通过" : "失败") << "\n";
    if (!bob_chain_ok) {
        std::cout << "  验证失败，用户选择退出。\n";
        return 1;
    }

    std::cout << "  步骤2: 用发送端签名私钥对邮件 Hash 值签名 (s = sig(H(m)))\n";
    std::cout << "  步骤3: 从 Bob 的证书中取出加密公钥\n";
    std::cout << "  步骤4: 用 Bob 的加密公钥加密 m||s\n";
    const std::string ciphertext = umbra::mail::send_mail(
        mail_content,
        alice.signature_private_key(),
        library,
        "Bob",
        ca_root.public_key()
    );
    write_file(mail_dir / "mail_ciphertext.txt", ciphertext);
    std::cout << "  步骤5: 发送密文 c (" << ciphertext.size() << " 字节):\n"
              << ciphertext << "\n";

    std::cout << "\n[接收端 Bob]\n"
              << "  步骤1: 用接收端加密私钥解密 c, 得到 m||s\n";
    std::cout << "  步骤2: 在证书库中查询 Alice 的签名公钥证书链并验证...\n";
    const std::string recovered = umbra::mail::receive_mail(
        ciphertext,
        bob.encryption_private_key(),
        library,
        "Alice",
        ca_root.public_key()
    );
    write_file(mail_dir / "mail_recovered.txt", recovered);
    std::cout << "  步骤3: 从 Alice 的证书中取出发送端签名公钥\n";
    std::cout << "  步骤4: 用发送端签名公钥验证签名\n";
    std::cout << "Bob 解密并验证后的邮件内容:\n" << recovered << "\n";
    std::cout << "邮件完整性与发送者身份验证: "
              << (recovered == mail_content ? "通过" : "失败") << "\n";

    std::cout << "产物目录: " << pki_dir.string() << " / " << mail_dir.string() << "\n";
    return (bob_chain_ok && recovered == mail_content) ? 0 : 1;
}

// A small terminal mail client used for live demonstrations.  It keeps the
// encrypted messages in memory (the mail protocol itself still only exchanges
// ciphertext strings) and exposes the same certificate/PKE steps as the
// scripted demo without requiring a GUI or a network service.
struct InteractiveMailbox {
    std::string sender;
    std::string recipient;
    std::string subject;
    std::string ciphertext;
    bool read = false;
};

struct InteractiveContext {
    CertificateAuthority root;
    CertificateAuthority ca1;
    CertificateAuthority ca2;
    CertificateLibrary library;
    std::map<std::string, std::unique_ptr<PkiUser>> users;
    std::vector<InteractiveMailbox> mailboxes;
    mutable std::mutex mutex;
    std::vector<std::string> logs;
    std::string status = "READY";

    void log(const std::string& message) {
        std::lock_guard<std::mutex> lock(mutex);
        logs.push_back(message);
        if (logs.size() > 4000) {
            logs.erase(logs.begin(), logs.begin() + 1000);
        }
    }

    void log_step(const std::string& phase, const std::string& message) {
        log("[" + phase + "] " + message);
    }

    void set_status(const std::string& value) {
        std::lock_guard<std::mutex> lock(mutex);
        status = value;
    }

    std::pair<std::string, std::vector<std::string>> snapshot() const {
        std::lock_guard<std::mutex> lock(mutex);
        return {status, logs};
    }

    InteractiveContext()
        : root("CA_root", CryptoType::RSA, 256),
          ca1("CA1", CryptoType::Elgamal, 256),
          ca2("CA2", CryptoType::RSA, 256),
          library("CA_root", root.public_key()) {
        auto store = [this](const Certificate& cert) {
            if (!library.store(cert)) {
                throw std::runtime_error("failed to store interactive certificate");
            }
        };
        const Certificate root_cert = root.self_sign();
        const Certificate ca1_cert = root.issue_certificate(
            ca1.AuthorityId(), ca1.public_key_text(), KeyPurpose::Signature);
        const Certificate ca2_cert = root.issue_certificate(
            ca2.AuthorityId(), ca2.public_key_text(), KeyPurpose::Signature);
        store(root_cert);
        store(ca1_cert);
        store(ca2_cert);

        log("[BOOT] interactive session initialized; default user: Alice");
        log_step("BOOT", "generated CA_root key pair (RSA, 256-bit demo parameters)");
        log_step("BOOT", "created and self-signed CA_root certificate");
        log_step("BOOT", "generated CA1 key pair (Elgamal, 256-bit demo parameters)");
        log_step("BOOT", "issued CA1 certificate signed by CA_root");
        log_step("BOOT", "generated CA2 key pair (RSA, 256-bit demo parameters)");
        log_step("BOOT", "issued CA2 certificate signed by CA_root");

        users.emplace("Alice", std::make_unique<PkiUser>(
            "Alice", CryptoType::RSA, CryptoType::RSA, 256));
        users.emplace("Bob", std::make_unique<PkiUser>(
            "Bob", CryptoType::Elgamal, CryptoType::RSA, 256));
        users.emplace("Eve", std::make_unique<PkiUser>(
            "Eve", CryptoType::RSA, CryptoType::Elgamal, 256));
        users.at("Alice")->apply_for_certificates(ca1);
        users.at("Bob")->apply_for_certificates(ca2);
        users.at("Eve")->apply_for_certificates(ca1);
        for (const auto& item : users) {
            const auto& user = *item.second;
            log_step("BOOT", "generated " + item.first + " encryption key pair (" +
                     (user.encryption_public_key().type() == CryptoType::RSA ? "RSA" : "Elgamal") + ")");
            log_step("BOOT", "generated " + item.first + " signature key pair (" +
                     (user.signature_public_key().type() == CryptoType::RSA ? "RSA" : "Elgamal") + ")");
            for (const auto& cert : user.certificates()) {
                store(cert);
                log_step("BOOT", "issued " + item.first + " " +
                         purpose_label(cert.Purpose()) + " certificate by " + cert.Issuer());
            }
        }
        log("[BOOT] certificate store ready: " + std::to_string(library.size()) +
            " certificates; Alice is selected");
    }
};

std::string read_line(const std::string& prompt) {
    std::cout << prompt << std::flush;
    std::string value;
    if (!std::getline(std::cin, value)) {
        throw std::runtime_error("input closed");
    }
    return value;
}

std::string trim_copy(const std::string& input) {
    const auto first = input.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) {
        return {};
    }
    const auto last = input.find_last_not_of(" \t\r\n");
    return input.substr(first, last - first + 1);
}

std::string read_multiline_body() {
    std::cout << "Enter the message body. Finish with a single '.' line.\n";
    std::string body;
    std::string line;
    while (std::getline(std::cin, line)) {
        if (line == ".") {
            break;
        }
        if (!body.empty()) {
            body.push_back('\n');
        }
        body += line;
    }
    return body;
}

void print_chain(const CertificatePath& path) {
    for (std::size_t i = 0; i < path.certificates.size(); ++i) {
        const auto& cert = path.certificates[i];
        std::cout << "  " << (i + 1) << ". " << cert.Subject()
                  << " (issued by " << cert.Issuer() << ", purpose="
                  << purpose_label(cert.Purpose()) << ")\n";
    }
}

void interactive_list_inbox(InteractiveContext& context, const std::string& user) {
    std::cout << "\nInbox for " << user << ":\n";
    bool any = false;
    std::lock_guard<std::mutex> lock(context.mutex);
    for (std::size_t i = 0; i < context.mailboxes.size(); ++i) {
        const auto& mail = context.mailboxes[i];
        if (mail.recipient != user) {
            continue;
        }
        any = true;
        std::cout << "  [" << i << "] " << (mail.read ? " " : "*")
                  << " from " << mail.sender << " - " << mail.subject << "\n";
    }
    if (!any) {
        std::cout << "  (no mail)\n";
    }
}

void interactive_read_mail(InteractiveContext& context, const std::string& user) {
    interactive_list_inbox(context, user);
    const std::string index_text = read_line("Mail index (blank to cancel): ");
    if (index_text.empty()) {
        return;
    }
    try {
        const std::size_t index = std::stoul(index_text);
        std::string sender;
        std::string ciphertext;
        std::string subject;
        {
            std::lock_guard<std::mutex> lock(context.mutex);
            if (index >= context.mailboxes.size() ||
                context.mailboxes[index].recipient != user) {
                std::cout << "Invalid mail index.\n";
                return;
            }
            sender = context.mailboxes[index].sender;
            ciphertext = context.mailboxes[index].ciphertext;
            subject = context.mailboxes[index].subject;
        }
        const auto& receiver = *context.users.at(user);
        context.set_status("DECRYPTING");
        context.log("[RX] " + user + " started decrypting incoming ciphertext");
        const std::string recovered = umbra::mail::receive_mail(
            ciphertext, receiver.encryption_private_key(), context.library,
            sender, context.root.public_key());
        {
            std::lock_guard<std::mutex> lock(context.mutex);
            context.mailboxes[index].read = true;
            context.status = "READY";
        }
        context.log("[RX] certificate chain verified for " + sender);
        context.log("[RX] signature verified; message accepted");
        const std::string separator = "\n\n";
        const std::size_t body_offset = recovered.find(separator);
        const std::string body = (body_offset == std::string::npos)
            ? recovered
            : recovered.substr(body_offset + separator.size());
        std::cout << "Certificate chain verified and signature valid.\n"
                  << "From: " << sender << "\n"
                  << "Subject: " << subject << "\n\n"
                  << body << "\n";
    } catch (const std::exception& error) {
        std::cout << "Cannot open mail: " << error.what() << "\n";
    }
}

void interactive_send_mail(InteractiveContext& context, const std::string& sender) {
    const std::string recipient = read_line("To (Alice/Bob/Eve): ");
    if (context.users.find(recipient) == context.users.end() || recipient == sender) {
        std::cout << "Unknown recipient (or recipient is the current user).\n";
        return;
    }
    const std::string subject = read_line("Subject: ");
    const std::string body = read_multiline_body();
    const std::string message = "Subject: " + subject + "\n\n" + body;
    try {
        const auto& sender_user = *context.users.at(sender);
        context.set_status("SENDING");
        context.log("[TX] " + sender + " -> " + recipient + ": querying encryption certificate");
        const CertificatePath path = context.library.query(
            recipient, KeyPurpose::Encryption);
        if (!umbra::certificate::verify_certificate_path(
                path, context.root.public_key())) {
            throw std::runtime_error("certificate chain is not trusted");
        }
        context.log("[TX] receiver chain verified: " + std::to_string(path.certificates.size()) + " certificates");
        context.log("[TX] signing SHA-256 digest with " + sender + "'s key");
        const std::string ciphertext = umbra::mail::send_mail(
            message, sender_user.signature_private_key(), context.library,
            recipient, context.root.public_key());
        context.log("[TX] encrypted m || s with " + recipient + "'s public key (" +
                    std::to_string(ciphertext.size()) + " bytes)");
        {
            std::lock_guard<std::mutex> lock(context.mutex);
            context.mailboxes.push_back(
                InteractiveMailbox{sender, recipient, subject, ciphertext, false});
            context.status = "READY";
        }
        context.log("[TX] ciphertext queued for local delivery");
    } catch (const std::exception& error) {
        context.set_status("ERROR");
        context.log("[TX] failed: " + std::string(error.what()));
        std::cout << "Send failed: " << error.what() << "\n";
    }
}

void interactive_show_certificate(InteractiveContext& context) {
    const std::string id = read_line("User id (Alice/Bob/Eve): ");
    auto it = context.users.find(id);
    if (it == context.users.end()) {
        std::cout << "Unknown user.\n";
        return;
    }
    std::cout << "Signature certificate chain for " << id << ":\n";
    print_chain(context.library.query(id, KeyPurpose::Signature));
    std::cout << "Encryption certificate chain for " << id << ":\n";
    print_chain(context.library.query(id, KeyPurpose::Encryption));
}

std::string tui_cell(std::string value, std::size_t width) {
    if (value.size() > width) {
        value.resize(width);
    }
    value.resize(width, ' ');
    return value;
}

std::vector<std::string> wrap_log_line(const std::string& line,
                                       std::size_t width) {
    if (line.empty()) {
        return {""};
    }
    const bool has_log_prefix = line.rfind("| ", 0) == 0;
    const std::string prefix = has_log_prefix ? "| " : "";
    const std::string content = has_log_prefix ? line.substr(2) : line;
    const std::size_t content_width = has_log_prefix
        ? (width > prefix.size() ? width - prefix.size() : 1)
        : width;
    std::vector<std::string> wrapped;
    for (std::size_t offset = 0; offset < content.size(); offset += content_width) {
        wrapped.push_back(prefix + content.substr(offset, content_width));
    }
    return wrapped;
}

void print_full_log(const InteractiveContext& context) {
    const auto snapshot = context.snapshot();
    constexpr std::size_t width = 112;
    std::cout << "\n================ FULL CRYPTO LOG (" << snapshot.second.size()
              << " entries) ================\n"
              << "STATUS: " << snapshot.first << "\n";
    for (const auto& entry : snapshot.second) {
        for (const auto& line : wrap_log_line(entry, width)) {
            std::cout << line << '\n';
        }
    }
    std::cout << "================ END CRYPTO LOG ================\n"
              << "Press Enter to return to the mailbox..." << std::flush;
    std::string ignored;
    std::getline(std::cin, ignored);
}

void render_tui(const InteractiveContext& context, const std::string& user,
                const std::string& hint = "") {
    // Keep the default TUI compact enough for a normal terminal window while
    // retaining the separate full-log view for longer demonstrations.
    constexpr std::size_t left_width = 30;
    constexpr std::size_t right_width = 72;
    constexpr std::size_t log_rows = 24;
    const auto snapshot = context.snapshot();
    std::vector<InteractiveMailbox> inbox;
    {
        std::lock_guard<std::mutex> lock(context.mutex);
        for (const auto& mail : context.mailboxes) {
            if (mail.recipient == user) {
                inbox.push_back(mail);
            }
        }
    }

    std::vector<std::string> left;
    left.push_back("UMBRA MAIL  " + user + "@umbra");
    left.push_back("CURRENT USER: " + user + (user == "Alice" ? " (default)" : ""));
    left.push_back("INBOX");
    if (inbox.empty()) {
        left.push_back("  (empty)");
    } else {
        for (std::size_t i = 0; i < inbox.size() && i < 8; ++i) {
            const auto& mail = inbox[i];
            left.push_back("  [" + std::to_string(i) + "] " +
                           (mail.read ? " " : "*") + " " + mail.sender +
                           " - " + mail.subject);
        }
    }
    left.push_back("");
    left.push_back("[1] refresh inbox");
    left.push_back("[2] read mail");
    left.push_back("[3] compose and send");
    left.push_back("[4] switch user");
    left.push_back("[5] show certificate chain");
    left.push_back("[6] show full crypto log");
    left.push_back("[7] clear crypto log");
    left.push_back("[q] quit");

    std::vector<std::string> right;
    right.push_back("BACKGROUND CRYPTO LOG");
    right.push_back("STATUS: " + snapshot.first);
    right.push_back("");
    std::vector<std::string> expanded_logs;
    for (const auto& entry : snapshot.second) {
        const auto wrapped = wrap_log_line(entry, right_width - 2);
        expanded_logs.insert(expanded_logs.end(), wrapped.begin(), wrapped.end());
    }
    const std::size_t start = expanded_logs.size() > log_rows
        ? expanded_logs.size() - log_rows : 0;
    if (expanded_logs.empty()) {
        right.push_back("(no log entries yet)");
    } else {
        for (std::size_t i = start; i < expanded_logs.size(); ++i) {
            right.push_back(expanded_logs[i]);
        }
    }

    const std::size_t rows = std::max(left.size(), right.size());
    std::cout << "\x1b[2J\x1b[H"
              << '+' << std::string(left_width + 2, '-') << "+ +"
              << std::string(right_width + 2, '-') << "+\n";
    for (std::size_t row = 0; row < rows; ++row) {
        const std::string left_text = row < left.size() ? left[row] : "";
        const std::string right_text = row < right.size() ? right[row] : "";
        std::cout << "| " << tui_cell(left_text, left_width)
                  << " | | " << tui_cell(right_text, right_width)
                  << " |\n";
    }
    std::cout << '+' << std::string(left_width + 2, '-') << "+ +"
              << std::string(right_width + 2, '-') << "+\n";
    if (!hint.empty()) {
        std::cout << hint << "\n";
    }
    std::cout << "> " << std::flush;
}

void run_background_job(InteractiveContext& context, const std::string& user,
                        const std::function<void()>& job) {
    std::atomic<bool> done{false};
    std::exception_ptr failure;
    std::thread worker([&]() {
        try {
            job();
        } catch (const std::exception& error) {
            failure = std::current_exception();
            context.set_status("ERROR");
            context.log("[ERR] " + std::string(error.what()));
        }
        done = true;
    });
    while (!done) {
        render_tui(context, user, "Working in background... please wait");
        std::this_thread::sleep_for(std::chrono::milliseconds(120));
    }
    worker.join();
    if (failure) {
        std::rethrow_exception(failure);
    }
    render_tui(context, user, "Background job finished. Press Enter to continue.");
    std::string ignored;
    std::getline(std::cin, ignored);
}

void send_mail_job(InteractiveContext& context, const std::string& sender,
                   const std::string& recipient, const std::string& subject,
                   const std::string& body) {
    const auto& sender_user = *context.users.at(sender);
    const std::string message = "Subject: " + subject + "\n\n" + body;
    context.set_status("QUERY CERT");
    context.log("[TX] query " + recipient + " encryption certificate");
    const CertificatePath path = context.library.query(recipient, KeyPurpose::Encryption);
    if (!umbra::certificate::verify_certificate_path(path, context.root.public_key())) {
        throw std::runtime_error("receiver certificate chain is not trusted");
    }
    context.log("[TX] chain verified (" + std::to_string(path.certificates.size()) + " certs)");
    context.log_step("TX", "selected " + recipient + " encryption certificate (leaf; contents hidden)");
    context.log_step("TX", "loaded " + recipient + " encryption public key (contents hidden)");
    context.log_step("TX", "loaded " + sender + " signature private key (contents hidden)");
    context.log_step("TX", "computed SHA-256 digest for plaintext (" +
                     std::to_string(message.size()) + " bytes; digest hidden)");
    context.set_status("SIGNING");
    const std::string signed_mail = umbra::mail::sign_mail(
        message, sender_user.signature_private_key());
    const umbra::mail::SignedMail parsed_signed =
        umbra::mail::parse_signed_mail(signed_mail);
    context.log("[TX] SHA-256 digest signed by " + sender);
    context.log_step("TX", "created signature s (" +
                     std::to_string(parsed_signed.signature.size()) + " bytes; value hidden)");
    context.log_step("TX", "assembled signed payload m || s (" +
                     std::to_string(signed_mail.size()) + " bytes; content hidden)");
    context.set_status("ENCRYPTING");
    auto receiver_public_key = umbra::certificate::parse_public_key(
        path.certificates.back().SubjectPublicKey());
    if (receiver_public_key == nullptr) {
        throw std::runtime_error("cannot parse receiver encryption public key");
    }
    const std::string ciphertext = umbra::mail::encrypt_mail(
        signed_mail, *receiver_public_key);
    context.log_step("TX", "generated ciphertext c (" +
                     std::to_string(ciphertext.size()) + " bytes; value hidden)");
    {
        std::lock_guard<std::mutex> lock(context.mutex);
        context.mailboxes.push_back({sender, recipient, subject, ciphertext, false});
        context.status = "READY";
    }
    context.log("[TX] queued for local delivery");
}

void read_mail_job(InteractiveContext& context, const std::string& user,
                   std::size_t index, std::string& recovered, std::string& sender,
                   std::string& subject) {
    std::string ciphertext;
    {
        std::lock_guard<std::mutex> lock(context.mutex);
        std::size_t visible = 0;
        for (const auto& mail : context.mailboxes) {
            if (mail.recipient != user) continue;
            if (visible++ == index) {
                sender = mail.sender;
                subject = mail.subject;
                ciphertext = mail.ciphertext;
                break;
            }
        }
    }
    if (ciphertext.empty()) throw std::runtime_error("invalid mail index");
    context.set_status("DECRYPTING");
    context.log("[RX] decrypting ciphertext with " + user + "'s private key");
    const auto& receiver = *context.users.at(user);
    context.log_step("RX", "loaded " + user + " encryption private key (contents hidden)");
    const std::string signed_mail = umbra::mail::decrypt_mail(
        ciphertext, receiver.encryption_private_key());
    const umbra::mail::SignedMail parsed_signed =
        umbra::mail::parse_signed_mail(signed_mail);
    context.log_step("RX", "decrypted ciphertext into signed payload m || s (" +
                     std::to_string(signed_mail.size()) + " bytes; content hidden)");
    context.log_step("RX", "recomputed SHA-256(m) (digest hidden)");
    const CertificatePath sender_path = context.library.query(
        sender, KeyPurpose::Signature);
    if (!umbra::certificate::verify_certificate_path(
            sender_path, context.root.public_key())) {
        throw std::runtime_error("sender certificate chain is not trusted");
    }
    context.log_step("RX", "selected " + sender + " signature certificate (leaf; contents hidden)");
    context.log_step("RX", "loaded " + sender + " signature public key (contents hidden)");
    const auto sender_public_key = umbra::certificate::parse_public_key(
        sender_path.certificates.back().SubjectPublicKey());
    if (sender_public_key == nullptr || !umbra::mail::verify_mail(
            parsed_signed.message, parsed_signed.signature, *sender_public_key)) {
        throw std::runtime_error("mail signature verification failed");
    }
    recovered = parsed_signed.message;
    context.log("[RX] sender certificate chain verified: " + sender);
    context.log("[RX] signature verified; message accepted");
    {
        std::lock_guard<std::mutex> lock(context.mutex);
        std::size_t visible = 0;
        for (auto& mail : context.mailboxes) {
            if (mail.recipient == user && visible++ == index) {
                mail.read = true;
                break;
            }
        }
        context.status = "READY";
    }
}

int run_interactive_demo() {
    std::cout << "Umbra-Core secure mail demo (ASCII TUI)\n"
              << "Generating a small teaching PKI; no network or GUI is used.\n"
              << "Current user is Alice (default sender). Choose [3] or type 'send' to compose.\n"
              << std::flush;
    InteractiveContext context;
    std::string current_user = "Alice";
    while (true) {
        std::string command;
        try {
            render_tui(context, current_user);
            if (!std::getline(std::cin, command)) {
                std::cout << "\nInput closed. Goodbye.\n";
                break;
            }
        } catch (const std::exception&) {
            std::cout << "\nInput closed. Goodbye.\n";
            break;
        }
        command = trim_copy(command);
        if (command == "q" || command == "Q") {
            break;
        }
        try {
            std::string command_lower = command;
            std::transform(command_lower.begin(), command_lower.end(),
                           command_lower.begin(), [](unsigned char ch) {
                               return static_cast<char>(std::tolower(ch));
                           });
            if (command_lower == "1") {
                render_tui(context, current_user, "Inbox refreshed. Press Enter to continue.");
                std::string ignored;
                std::getline(std::cin, ignored);
            } else if (command_lower == "2") {
                render_tui(context, current_user, "Enter visible inbox index (blank to cancel):");
                std::string index_text;
                if (!std::getline(std::cin, index_text) || index_text.empty()) {
                    continue;
                }
                const std::size_t index = std::stoul(index_text);
                std::string recovered;
                std::string sender;
                std::string subject;
                run_background_job(context, current_user, [&]() {
                    read_mail_job(context, current_user, index, recovered, sender, subject);
                });
                const std::string separator = "\n\n";
                const std::size_t body_offset = recovered.find(separator);
                const std::string body = (body_offset == std::string::npos)
                    ? recovered
                    : recovered.substr(body_offset + separator.size());
                std::cout << "\nFrom: " << sender << "\nSubject: " << subject
                          << "\n\n" << body << "\n\n"
                          << "Signature and certificate chain verified.\n"
                          << "Press Enter to return to the mailbox..." << std::flush;
                std::string ignored;
                std::getline(std::cin, ignored);
            } else if (command_lower == "3" || command_lower == "s" ||
                       command_lower == "send" || command_lower == "compose") {
                const std::string recipient = read_line("To (Alice/Bob/Eve): ");
                if (context.users.find(recipient) == context.users.end() ||
                    recipient == current_user) {
                    std::cout << "Unknown recipient (or recipient is the current user).\n";
                    continue;
                }
                const std::string subject = read_line("Subject: ");
                const std::string body = read_multiline_body();
                run_background_job(context, current_user, [&]() {
                    send_mail_job(context, current_user, recipient, subject, body);
                });
            } else if (command_lower == "4") {
                const std::string next = read_line("Switch to (Alice/Bob/Eve): ");
                if (context.users.find(next) == context.users.end()) {
                    std::cout << "Unknown user.\n";
                } else {
                    current_user = next;
                }
            } else if (command_lower == "5") {
                const std::string id = read_line("User id (Alice/Bob/Eve): ");
                if (context.users.find(id) == context.users.end()) {
                    std::cout << "Unknown user.\n";
                    continue;
                }
                std::cout << "\nSignature certificate chain for " << id << ":\n";
                print_chain(context.library.query(id, KeyPurpose::Signature));
                std::cout << "Encryption certificate chain for " << id << ":\n";
                print_chain(context.library.query(id, KeyPurpose::Encryption));
                std::cout << "Press Enter to continue..." << std::flush;
                std::string ignored;
                std::getline(std::cin, ignored);
            } else if (command_lower == "6") {
                print_full_log(context);
            } else if (command_lower == "7") {
                {
                    std::lock_guard<std::mutex> lock(context.mutex);
                    context.logs.clear();
                    context.status = "READY";
                }
                render_tui(context, current_user,
                            "Crypto log cleared. Press Enter to continue.");
                std::string ignored;
                std::getline(std::cin, ignored);
            } else {
                std::cout << "Unknown command. Enter 1-7 or q.\n";
            }
        } catch (const std::exception& error) {
            std::cout << "Operation failed: " << error.what() << "\n";
            if (!std::cin) {
                break;
            }
        }
    }
    std::cout << "Goodbye.\n";
    return 0;
}

} // namespace

int main(int argc, char* argv[]) {
    if (argc == 1 || (argc > 1 && std::string(argv[1]) == "--interactive")) {
        return run_interactive_demo();
    }
    if (argc > 1 && (std::string(argv[1]) == "--help" ||
                     std::string(argv[1]) == "-h")) {
        std::cout << "Usage:\n"
                  << "  umbra_demo                 interactive terminal mail demo\n"
                  << "  umbra_demo --interactive  same as above\n"
                  << "  umbra_demo --batch [input] [output]  scripted five-task demo\n";
        return 0;
    }
    const int argument_offset =
        (argc > 1 && std::string(argv[1]) == "--batch") ? 1 : 0;
    // 用法: umbra_demo [输入文件] [输出目录]
    //   输入文件（可选）: 用于 RSA/Elgamal 加密与邮件内容的明文文件;
    //   输出目录（可选）: 存放密钥、证书、密文等产物, 默认 ./demo_output。
    const std::filesystem::path input_file =
        (argc > 1 + argument_offset)
            ? std::filesystem::path(argv[1 + argument_offset])
            : std::filesystem::path();
    const std::filesystem::path output_dir =
        (argc > 2 + argument_offset) ? std::filesystem::path(argv[2 + argument_offset])
                   : std::filesystem::path("demo_output");
    std::filesystem::create_directories(output_dir);

    std::cout << "现代密码学课程设计 —— Umbra-Core 演示程序\n"
              << "输入文件: " << (input_file.empty() ? "(内置示例)" : input_file.string())
              << "\n输出目录: " << output_dir.string() << "\n";

    int result = 0;
    result += demo_rsa(input_file, output_dir);
    result += demo_elgamal(input_file, output_dir);
    result += demo_certificate(output_dir);
    result += demo_pki_and_mail(input_file, output_dir);

    if (result != 0) {
        std::cerr << "\n演示程序有部分步骤失败\n";
        return 1;
    }
    std::cout << "\n所有任务演示完成。\n";
    return 0;
}
