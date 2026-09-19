#include <sys/inotify.h>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>
#include <fnmatch.h>
#include <unistd.h>
#include <fstream>
#include <iostream>
#include <sys/stat.h> // Содержит функцию chmod
#include <thread>
#include <atomic> 
#include <openssl/evp.h> // Вместо openssl/sha.h
#include <mutex>
#include <glob.h> // Для работы с масками имен файлов

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

std::atomic<bool> is_protected(true); // Флаг защиты

std::vector<std::string> locked_files;
std::mutex files_mutex; // Чтобы потоки не подрались за вектор

void unlock_all() {
    // Снимаем атрибут 'i' со всех файлов в текущей директории
    // 2>/dev/null нужно, чтобы не было ошибок, если в папке нет файлов с атрибутом 'i'
    system("chattr -i * 2>/dev/null");
    std::cout << "Защита снята со всех файлов!" << std::endl;
}


void lock_all(const std::vector<std::string>& file_mask) {
    for (const auto& pattern : file_mask) {
        glob_t glob_result;
        // glob находит все файлы, соответствующие паттерну (например, *.txt)
        if (glob(pattern.c_str(), GLOB_TILDE, NULL, &glob_result) == 0) {
            for (size_t i = 0; i < glob_result.gl_pathc; ++i) {
                std::string cmd = "chattr +i " + std::string(glob_result.gl_pathv[i]);
                system(cmd.c_str());
            }
            globfree(&glob_result);
        }
    }
    std::cout << "Защита наложена." << std::endl;
}

void password_thread(std::string stored_hash, std::vector<std::string> file_mask) {
    std::string input;
    while(true) {
        std::cin >> input;

        if(input == "exit") {
            std::cout << "Завершение программы" << std::endl;
            exit(0);
        }

        if(sha256(input) == stored_hash) {
            is_protected = !is_protected;
            std::cout << "Режим защиты: " << (is_protected ? "ВКЛ" : "ВЫКЛ") << std::endl;
            
            if (!is_protected) {
                std::cout << "Вызываю unlock_all..." << std::endl; // ТЕСТОВЫЙ ВЫВОД
                unlock_all();
            } else {
                std::cout << "Вызываю lock_all..." << std::endl; // ТЕСТОВЫЙ ВЫВОД
                lock_all(file_mask);
            }
        }
    }
}



int main() {

    chmod("template.tbl", 0600);
    std::vector<std::string> file_mask;
    std::string hash;
    std::string line;

    std::ifstream file("template.tbl");
    if(!file.is_open()) { /* обработка ошибки */ }

    std::getline(file, hash); // Считали хэш
    while(std::getline(file, line)) { // Считали маски
        if(!line.empty()) file_mask.push_back(line);
    }
    file.close(); // Закрываем файл

    std::cout << "Введите пароль для переключения режима!" << std::endl;
    // Теперь передаем ЗАПОЛНЕННЫЙ вектор в поток
    std::thread t(password_thread, hash, file_mask); 
    t.detach();

    while(std::getline(file, line)) {
        if(!line.empty()) {
            file_mask.push_back(line);
        }
    }

    lock_all(file_mask); // Блокируем всё, что уже есть

    int fd = inotify_init(); // Это создается очереть, в которую ядро складывает записи о событиях
    int wd = inotify_add_watch(fd, ".", IN_CREATE | IN_DELETE | IN_MODIFY | IN_MOVED_FROM | IN_MOVED_TO); // Тут мы говорим, в какой папке слушать события и какие события слушать

    char buffer[4096]; 

    if (wd == -1) {
        perror("Ошибка при добавлении в мониторинг");
    }


    while(true) {
        int length = read(fd, buffer, sizeof(buffer));
        if (length < 0) break;

        int i = 0; 
        while (i < length) {
            struct inotify_event *event = (struct inotify_event *) &buffer[i];
            
            if (event->len > 0 && (event->mask & IN_CREATE || event->mask & IN_MOVED_TO)) {
                    for (const auto& pattern : file_mask) {
                        if (fnmatch(pattern.c_str(), event->name, 0) == 0) {
                            
                            if (is_protected) {
                                // ПРЕДОТВРАЩАЕМ создание:
                                unlink(event->name); 
                                std::cout << "Файл " << event->name << " запрещен и удален!" << std::endl;
                            }
                            break; 
                        }
                    }
                }
            i += sizeof(struct inotify_event) + event->len;
        }
    }


}