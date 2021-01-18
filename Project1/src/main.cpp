#include <string>
#include <iostream>
#include <cstring>
#include <chrono>
#include <thread>
#include <vector>
#include <sys/sysinfo.h>

#include <openssl/md5.h>

const std::string base64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const std::string salt = "4fTgjp6q";
const std::string goal = "5eNsoUHeovBd6S4E2BJWS1";
static bool found = false;
const int RANGE = 23762752;
static int lines = 0;

void incrementStr(std::string &str, const int amount = 1) {

}

std::string to64(unsigned long long v, int n) {
    std::string result = "";
    for (int i = 0; i < n; i++) {
        result += base64[v&0x3f];
        v >>= 6;
    }

    return result;
}

unsigned char* md5(const std::string& pw) {
    MD5_CTX context;
    unsigned char* final = (unsigned char*)malloc(16);

    MD5_Init(&context);
    MD5_Update(&context, pw.c_str(), pw.length());
    MD5_Final(final, &context);
 
    return final;
}

std::string md5_encrypt(const std::string& password, const std::string& salt) {
    const std::string magic = "$1$";
    std::string res = password + magic + salt;

    unsigned char* h = md5(password + salt + password);

    int l = password.length();
    while (l > 0) {
        for (int i = 0; i < std::min(16, l); i++)
            res.push_back(h[i]);
        l -= 16;
    }
    
    for (int i = password.length(); i != 0; i >>= 1) {
        if (i & 1) res += '\x00';
        else res += password[0];
    }

    free(h);

    h = md5(res);

    for (int i = 0; i < 1000; i++) {
        std::string interm = "";
        for(unsigned int k = 0; k < 16; k++)
			interm.push_back(h[k]);

        free(h);

        std::string tmp = "";
        if (i % 2 == 1) tmp += password;
        else tmp += interm;

        if (i % 3 != 0) tmp += salt;
        if (i % 7 != 0) tmp += password;

        if (i % 2 == 1) tmp += interm;
        else tmp += password;

        h = md5(tmp);
    }
    
    std::string hash = to64((h[0] << 16) | (h[6] << 8) | h[12], 4) +
            to64((h[1] << 16) | (h[7] << 8) | h[13], 4) + 
            to64((h[2] << 16) | (h[8] << 8) | h[14], 4) +
            to64((h[3] << 16) | (h[9] << 8) | h[15], 4) +
            to64((h[4] << 16) | (h[10] << 8) | h[5], 4) +
            to64(h[11], 2);

    free(h);

    return hash;
}

void start(int thread_id) {
    const char l = 'a' + 2 * thread_id;
    const char u = (thread_id == 12 ? l + 1 : l + 2);
    std::string lower(5, 'a');
    std::string upper(5, 'a');
    lower += l;
    upper += u;
    if (thread_id == 13) {
        lower = "aaaaaz";
        upper = "zzzzzz";
    }

    std::string result;

    // std::cout << "Thread " << thread_id << " is checking from " << lower << " to " << upper << std::endl;

    while (!found && lower != upper) {
        result = md5_encrypt(lower, salt);
        lines++;

        //std::cout << "Thread " << thread_id << " is checking: " << lower << std::endl;

        if (result == goal) {
            std::cout << "Password Cracked: " << lower << std::endl;
            found = true;
            break;
        } else {
            int level = 0;
            while (level < 6) {
                if (lower[level] == 0) {
                    lower[level] = 'a';
                    break;
                }
                if (lower[level] >= 'a' && lower[level] < 'z') {
                    lower[level]++;
                    break;
                }
                if (lower[level] == 'z') {
                    lower[level] = 'a';
                    level++;
                }
            }
        }
    }
}

int main(int argc, char** argv) {
    //std::cout << md5_encrypt("ssssss", "4fTgjp6q") << std::endl;
    int thread_count = 14;

    printf("CPU: Intel Core i9-9900k\n");
    printf("    Total cores available: %d.\n", get_nprocs());
    printf("    Launching %d threads.\n", thread_count);

    std::vector<std::thread> threads;

    auto started = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < thread_count; i ++) {
        threads.push_back(std::thread(start, i));
    }

    for (auto &th : threads) {
        th.join();
    }
    
    auto done = std::chrono::high_resolution_clock::now();
    auto seconds = std::chrono::duration_cast<std::chrono::milliseconds>(done-started).count() / 1000;
    std::cout << "This process used " << seconds << " seconds." << std::endl;
    std::cout << lines << " passwords were tested, (" << lines / seconds << " passwords/s)\n" << std::endl;
    
    return 0;
}