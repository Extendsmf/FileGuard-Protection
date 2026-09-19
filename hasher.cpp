#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <openssl/evp.h> // Вместо openssl/sha.h

std::string sha256(const std::string& str) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;

    // Создаем контекст для хеширования
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    
    // Инициализируем контекст для SHA256
    EVP_DigestInit_ex(context, EVP_sha256(), NULL);
    
    // Обновляем контекст данными
    EVP_DigestUpdate(context, str.c_str(), str.size());
    
    // Завершаем хеширование и получаем результат
    EVP_DigestFinal_ex(context, hash, &lengthOfHash);
    
    // Очищаем контекст (обязательно!)
    EVP_MD_CTX_free(context);

    // Превращаем байты в HEX-строку
    std::stringstream ss;
    for(unsigned int i = 0; i < lengthOfHash; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

int main() {
    std::string pass = "password";
    std::cout << "Hash: " << sha256(pass) << std::endl;
    return 0;
}