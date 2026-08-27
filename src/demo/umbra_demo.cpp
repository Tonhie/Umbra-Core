#include "certificate/certificate_authority.h"
#include "certificate/certificate_library.h"
#include "certificate/trusted_authority.h"
#include "crypto/crypto_engine.h"
#include "mail/secure_mail.h"
#include "pki/pki_user.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
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

} // namespace

int main(int argc, char* argv[]) {
    // 用法: umbra_demo [输入文件] [输出目录]
    //   输入文件（可选）: 用于 RSA/Elgamal 加密与邮件内容的明文文件;
    //   输出目录（可选）: 存放密钥、证书、密文等产物, 默认 ./demo_output。
    const std::filesystem::path input_file =
        (argc > 1) ? std::filesystem::path(argv[1]) : std::filesystem::path();
    const std::filesystem::path output_dir =
        (argc > 2) ? std::filesystem::path(argv[2])
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
