#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <random>
#include <chrono>
#include <thread>
#include <mutex>
#include <regex>
#include <iomanip>
#include <cstring>
#include <set>
#include <tuple>
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <openssl/md5.h>
#include <openssl/evp.h>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>

using json = nlohmann::json;
using namespace std;

const string BOT_TOKEN = "YOUR_BOT_TOKEN_HERE";
const string CONTACT_USERNAME = "@your_username";

vector<int64_t> ADMIN_USER_IDS = {123456789};

struct UserData {
    string session;
    string username;
    string userID;
    string deviceID;
    string familyDeviceID;
    string androidID;
    string uuid;
    string csrfToken;
    vector<uint8_t> postImage;
    vector<int> postDimensions;
};

map<int64_t, UserData*> userData;
map<int64_t, string> userStates;
map<int64_t, string> userPublicKeys;
mutex dataMutex;

struct WriteCallbackData {
    string data;
};

size_t WriteCallback(void* contents, size_t size, size_t nmemb, WriteCallbackData* data) {
    size_t totalSize = size * nmemb;
    data->data.append((char*)contents, totalSize);
    return totalSize;
}

bool IsAdmin(int64_t userID) {
    return find(ADMIN_USER_IDS.begin(), ADMIN_USER_IDS.end(), userID) != ADMIN_USER_IDS.end();
}

map<string, int64_t> LoadSubscribers() {
    map<string, int64_t> subs;
    ifstream file("subs.json");
    if (file.is_open()) {
        try {
            json j;
            file >> j;
            for (auto& item : j.items()) {
                subs[item.key()] = item.value();
            }
        } catch (...) {
        }
        file.close();
    }
    return subs;
}

bool SaveSubscribers(const map<string, int64_t>& subs) {
    json j = subs;
    ofstream file("subs.json");
    if (file.is_open()) {
        file << j.dump(2);
        file.close();
        return true;
    }
    return false;
}

pair<bool, int64_t> IsSubscribed(int64_t userID) {
    if (IsAdmin(userID)) {
        return {true, 0};
    }

    auto subs = LoadSubscribers();
    string userIDStr = to_string(userID);
    
    auto it = subs.find(userIDStr);
    if (it == subs.end()) {
        return {false, 0};
    }

    int64_t now = chrono::duration_cast<chrono::seconds>(chrono::system_clock::now().time_since_epoch()).count();
    if (now > it->second) {
        subs.erase(userIDStr);
        SaveSubscribers(subs);
        return {false, 0};
    }

    return {true, it->second - now};
}

bool AddSubscriber(int64_t userID, int durationDays) {
    auto subs = LoadSubscribers();
    string userIDStr = to_string(userID);
    
    auto now = chrono::system_clock::now();
    auto expiration = now + chrono::hours(24 * durationDays);
    int64_t expirationUnix = chrono::duration_cast<chrono::seconds>(expiration.time_since_epoch()).count();
    
    subs[userIDStr] = expirationUnix;
    return SaveSubscribers(subs);
}

bool RemoveSubscriber(int64_t userID) {
    auto subs = LoadSubscribers();
    string userIDStr = to_string(userID);
    subs.erase(userIDStr);
    return SaveSubscribers(subs);
}

int GetSubscriberCount() {
    auto subs = LoadSubscribers();
    int64_t now = chrono::duration_cast<chrono::seconds>(chrono::system_clock::now().time_since_epoch()).count();
    bool updated = false;
    
    for (auto it = subs.begin(); it != subs.end();) {
        if (now > it->second) {
            it = subs.erase(it);
            updated = true;
        } else {
            ++it;
        }
    }
    
    if (updated) {
        SaveSubscribers(subs);
    }
    
    return subs.size();
}

string FormatTimeRemaining(int64_t seconds) {
    if (seconds <= 0) {
        return "Expired";
    }

    int64_t days = seconds / 86400;
    int64_t hours = (seconds % 86400) / 3600;
    int64_t minutes = (seconds % 3600) / 60;
    int64_t secs = seconds % 60;

    stringstream ss;
    if (days > 0) {
        ss << days << " days, " << hours << " hours, " << minutes << " minutes, " << secs << " seconds";
    } else if (hours > 0) {
        ss << hours << " hours, " << minutes << " minutes, " << secs << " seconds";
    } else if (minutes > 0) {
        ss << minutes << " minutes, " << secs << " seconds";
    } else {
        ss << secs << " seconds";
    }
    
    return ss.str();
}

map<string, int64_t> LoadKeys() {
    map<string, int64_t> keys;
    ifstream file("keys.json");
    if (file.is_open()) {
        try {
            json j;
            file >> j;
            for (auto& item : j.items()) {
                keys[item.key()] = item.value();
            }
        } catch (...) {
        }
        file.close();
    }
    return keys;
}

bool SaveKeys(const map<string, int64_t>& keys) {
    json j = keys;
    ofstream file("keys.json");
    if (file.is_open()) {
        file << j.dump(2);
        file.close();
        return true;
    }
    return false;
}

string GenerateKey() {
    const string charset = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-";
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dist(0, charset.length() - 1);
    
    string key;
    for (int i = 0; i < 64; ++i) {
        key += charset[dist(gen)];
    }
    return key;
}

map<string, int64_t> LoadPublicKeys() {
    map<string, int64_t> keys;
    ifstream file("public_keys.json");
    if (file.is_open()) {
        try {
            json j;
            file >> j;
            for (auto& item : j.items()) {
                keys[item.key()] = item.value();
            }
        } catch (...) {
        }
        file.close();
    }
    return keys;
}

bool SavePublicKeys(const map<string, int64_t>& keys) {
    json j = keys;
    ofstream file("public_keys.json");
    if (file.is_open()) {
        file << j.dump(2);
        file.close();
        return true;
    }
    return false;
}

bool IsPublicKeyValid(const string& keyCode) {
    auto keys = LoadPublicKeys();
    auto it = keys.find(keyCode);
    if (it == keys.end()) {
        return false;
    }

    int64_t now = chrono::duration_cast<chrono::seconds>(chrono::system_clock::now().time_since_epoch()).count();
    if (now > it->second) {
        keys.erase(keyCode);
        SavePublicKeys(keys);
        return false;
    }

    return true;
}

pair<int64_t, bool> ParseTimeFormat(const string& timeStr) {
    if (timeStr.length() < 2) {
        return {0, false};
    }

    string unit = timeStr.substr(timeStr.length() - 1);
    string valueStr = timeStr.substr(0, timeStr.length() - 1);
    
    int64_t value = stoll(valueStr);
    
    if (unit == "m") {
        return {value * 60, true};
    } else if (unit == "h") {
        return {value * 3600, true};
    } else if (unit == "d") {
        return {value * 86400, true};
    } else if (unit == "w") {
        return {value * 604800, true};
    }
    
    return {0, false};
}

pair<bool, string> RedeemKey(int64_t userID, const string& keyCode) {
    auto keys = LoadKeys();
    auto it = keys.find(keyCode);
    if (it == keys.end()) {
        return {false, "Invalid or expired key"};
    }

    int64_t now = chrono::duration_cast<chrono::seconds>(chrono::system_clock::now().time_since_epoch()).count();
    if (now > it->second) {
        keys.erase(keyCode);
        SaveKeys(keys);
        return {false, "Key has expired"};
    }

    int subscriptionDays = max(1, (int)((it->second - now) / 86400));
    
    if (!AddSubscriber(userID, subscriptionDays)) {
        return {false, "Failed to add subscription"};
    }

    keys.erase(keyCode);
    SaveKeys(keys);

    return {true, "Key redeemed successfully! You now have " + to_string(subscriptionDays) + " days of subscription."};
}

string GenerateCSRFToken() {
    const string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dist(0, charset.length() - 1);
    
    string token;
    for (int i = 0; i < 32; ++i) {
        token += charset[dist(gen)];
    }
    return token;
}

string GenerateDeviceID(const string& id) {
    string volatileID = "12345";
    string combined = id + volatileID;
    
    unsigned char hash[MD5_DIGEST_LENGTH];
    MD5((unsigned char*)combined.c_str(), combined.length(), hash);
    
    stringstream ss;
    ss << "android-";
    for (int i = 0; i < 8; ++i) {
        ss << hex << setw(2) << setfill('0') << (unsigned int)hash[i];
    }
    
    return ss.str();
}

string GenerateUserAgent() {
    vector<string> devices = {"Device1", "Device2", "Device3", "Device4"};
    vector<string> dpis = {"480", "320", "640", "515"};
    
    random_device rd;
    mt19937 gen(rd());
    
    int randResolution = (gen() % 7 + 2) * 180;
    int lowerResolution = randResolution - 180;
    string manufacturer = devices[gen() % devices.size()];
    char modelChar1 = 'a' + (gen() % 26);
    char modelChar2 = 'a' + (gen() % 26);
    int modelNum1 = gen() % 10;
    int modelNum2 = gen() % 10;
    string model = manufacturer + "-" + modelChar1 + to_string(modelNum1) + modelChar2 + to_string(modelNum2);
    int androidVersion = gen() % 8 + 18;
    string androidRelease = to_string(gen() % 7 + 1) + "." + to_string(gen() % 8);
    char cpuChar1 = 'a' + (gen() % 26);
    char cpuChar2 = 'a' + (gen() % 26);
    string cpu = string(1, cpuChar1) + string(1, cpuChar2) + to_string(gen() % 9000 + 1000);
    string resolution = to_string(randResolution) + "x" + to_string(lowerResolution);
    string dpi = dpis[gen() % dpis.size()];
    
    char randomChar1 = 'a' + (gen() % 26);
    char randomChar2 = 'a' + (gen() % 26);
    char randomChar3 = 'a' + (gen() % 26);
    string randomL = string(1, randomChar1) + to_string(gen() % 10) + 
                     string(1, randomChar2) + to_string(gen() % 10) + 
                     string(1, randomChar3) + to_string(gen() % 10);

    stringstream ss;
    ss << "Instagram 155.0.0.37.107 Android (" << androidVersion << "/" << androidRelease 
       << "; " << dpi << "dpi; " << resolution << "; " << manufacturer << "; " << model 
       << "; " << cpu << "; " << randomL << "; en_US)";
    
    return ss.str();
}

string HttpGet(const string& url, const map<string, string>& headers = {}) {
    CURL* curl;
    WriteCallbackData responseData;

    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseData);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

        struct curl_slist* headerList = nullptr;
        for (const auto& header : headers) {
            string headerStr = header.first + ": " + header.second;
            headerList = curl_slist_append(headerList, headerStr.c_str());
        }
        if (headerList) {
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerList);
        }

        curl_easy_perform(curl);
        
        if (headerList) {
            curl_slist_free_all(headerList);
        }
        curl_easy_cleanup(curl);
    }

    return responseData.data;
}

string HttpPost(const string& url, const string& postData, const map<string, string>& headers = {}) {
    CURL* curl;
    WriteCallbackData responseData;

    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseData);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

        struct curl_slist* headerList = nullptr;
        for (const auto& header : headers) {
            string headerStr = header.first + ": " + header.second;
            headerList = curl_slist_append(headerList, headerStr.c_str());
        }
        if (headerList) {
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerList);
        }

        curl_easy_perform(curl);
        
        if (headerList) {
            curl_slist_free_all(headerList);
        }
        curl_easy_cleanup(curl);
    }

    return responseData.data;
}

tuple<bool, string, string> CheckSessionValid(const string& sessionText) {
    map<string, string> headers = {
        {"host", "i.instagram.com"},
        {"user-agent", GenerateUserAgent()},
        {"x-tigon-is-retry", "False"},
        {"x-fb-rmd", "state=URL_ELIGIBLE"},
        {"x-graphql-client-library", "pando"},
        {"x-ig-app-id", "567067343352427"},
        {"content-type", "application/x-www-form-urlencoded"},
        {"x-ig-capabilities", "3brTv10="},
        {"authorization", "Bearer IGT:2:" + sessionText},
        {"cookie", "sessionid=" + sessionText},
        {"accept-encoding", "zstd, gzip, deflate"},
        {"x-fb-http-engine", "Liger"},
        {"x-fb-client-ip", "True"},
        {"x-fb-server-cluster", "True"},
        {"connection", "keep-alive"}
    };

    json reqTags = {
        {"network_tags", {
            {"product", "567067343352427"},
            {"purpose", "none"},
            {"request_category", "graphql"},
            {"retry_attempt", "0"}
        }},
        {"application_tags", "pando"}
    };
    headers["x-fb-request-analytics-tags"] = reqTags.dump();

    json variables = {{"is_pando", true}};
    
    string payload = "method=post&pretty=false&format=json&server_timestamps=true&locale=en_GB&fb_api_req_friendly_name=HasAvatarQuery&client_doc_id=176575339118291536801493724773&enable_canonical_naming=true&enable_canonical_variable_overrides=true&enable_canonical_naming_ambiguous_type_prefixing=true&variables=" + variables.dump();

    string response = HttpPost("https://i.instagram.com/graphql_www", payload, headers);
    
    if (!response.empty()) {
        regex userIDRegex("\"user_id\":\"(\\d+)\"");
        regex usernameRegex("\"username\":\"([^\"\\\\]+)\"");
        
        smatch userIDMatch, usernameMatch;
        
        if (regex_search(response, userIDMatch, userIDRegex)) {
            string userID = userIDMatch[1];
            string username = "";
            if (regex_search(response, usernameMatch, usernameRegex)) {
                username = usernameMatch[1];
            }
            return {true, username, userID};
        }
        if (regex_search(response, usernameMatch, usernameRegex)) {
            return {true, usernameMatch[1], ""};
        }
    }

    map<string, string> webHeaders = {
        {"User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
        {"X-IG-App-ID", "567067343352427"},
        {"X-IG-WWW-Claim", "0"},
        {"Cookie", "sessionid=" + sessionText}
    };

    string webResponse = HttpGet("https://www.instagram.com/accounts/edit/", webHeaders);
    
    if (!webResponse.empty()) {
        regex userIDRegex("\"user_id\":\"(\\d+)\"");
        regex usernameRegex("\"username\":\"([^\"\\\\]+)\"");
        smatch userIDMatch, usernameMatch;
        
        if (regex_search(webResponse, userIDMatch, userIDRegex)) {
            string userID = userIDMatch[1];
            string username = "";
            if (regex_search(webResponse, usernameMatch, usernameRegex)) {
                username = usernameMatch[1];
            }
            return {true, username, userID};
        }
        if (regex_search(webResponse, usernameMatch, usernameRegex)) {
            return {true, usernameMatch[1], ""};
        }
    }

    return {false, "", ""};
}

string CreateUUID() {
    boost::uuids::uuid uuid = boost::uuids::random_generator()();
    return boost::uuids::to_string(uuid);
}

string GenerateRandomString(int n, bool upper = false) {
    string letters = upper ? "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890" : "abcdefghijklmnopqrstuvwxyz1234567890";
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dist(0, letters.length() - 1);
    
    string result;
    for (int i = 0; i < n; ++i) {
        result += letters[dist(gen)];
    }
    return result;
}

string GenerateRandomDigits(int n) {
    string digits = "1234567890";
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dist(0, digits.length() - 1);
    
    string result;
    for (int i = 0; i < n; ++i) {
        result += digits[dist(gen)];
    }
    return result;
}

void SendTelegramMessage(int64_t chatID, const string& text) {
    string url = "https://api.telegram.org/bot" + BOT_TOKEN + "/sendMessage";
    json payload = {
        {"chat_id", chatID},
        {"text", text}
    };
    
    map<string, string> headers = {
        {"Content-Type", "application/json"}
    };
    
    HttpPost(url, payload.dump(), headers);
}

void HandleStart(int64_t chatID) {
    SendTelegramMessage(chatID, "Welcome! Please check your subscription or enter a key to continue.");
}

bool RequireSubscription(int64_t chatID) {
    auto [subscribed, _] = IsSubscribed(chatID);
    if (!subscribed) {
        auto it = userPublicKeys.find(chatID);
        if (it != userPublicKeys.end()) {
            if (IsPublicKeyValid(it->second)) {
                return true;
            } else {
                userPublicKeys.erase(chatID);
            }
        }

        SendTelegramMessage(chatID, "You need an active subscription to use this feature. Contact " + CONTACT_USERNAME + " to subscribe or use the 'Enter Key' button for trial keys.");
        return false;
    }
    return true;
}

void HandleSessionInput(int64_t chatID, const string& sessionID) {
    auto [valid, username, userID] = CheckSessionValid(sessionID);
    if (valid) {
        string csrftoken = GenerateCSRFToken();
        
        lock_guard<mutex> lock(dataMutex);
        if (userData[chatID] == nullptr) {
            userData[chatID] = new UserData();
        }
        
        string deviceUUID = CreateUUID();
        userData[chatID]->session = sessionID;
        userData[chatID]->username = username.empty() ? "(unknown)" : username;
        userData[chatID]->userID = userID;
        userData[chatID]->deviceID = deviceUUID;
        userData[chatID]->familyDeviceID = CreateUUID();
        userData[chatID]->androidID = GenerateDeviceID(to_string(chrono::high_resolution_clock::now().time_since_epoch().count()));
        userData[chatID]->uuid = deviceUUID;
        userData[chatID]->csrfToken = csrftoken;

        SendTelegramMessage(chatID, "Successfully logged in as @" + userData[chatID]->username);
        userStates.erase(chatID);
    } else {
        SendTelegramMessage(chatID, "Invalid or expired session ID. Please provide a valid API session.");
        userStates.erase(chatID);
    }
}

void HandleKeyInput(int64_t chatID, const string& keyCode) {
    string trimmedKey = keyCode;
    boost::trim(trimmedKey);
    
    if (trimmedKey.empty()) {
        SendTelegramMessage(chatID, "Please enter a valid key.");
        return;
    }

    auto [success, message] = RedeemKey(chatID, trimmedKey);

    if (success) {
        SendTelegramMessage(chatID, message);
    } else {
        if (IsPublicKeyValid(trimmedKey)) {
            userPublicKeys[chatID] = trimmedKey;
            SendTelegramMessage(chatID, "Trial key accepted! You can now use the bot features.");
        } else {
            SendTelegramMessage(chatID, "Invalid or expired key. Please try again or contact support.");
        }
    }

    userStates.erase(chatID);
}

void HandleCheckSubscription(int64_t chatID) {
    auto [subscribed, timeRemaining] = IsSubscribed(chatID);

    if (subscribed) {
        if (IsAdmin(chatID)) {
            SendTelegramMessage(chatID, "You are verified as admin! You have unlimited access to all features.");
        } else {
            auto subs = LoadSubscribers();
            string userIDStr = to_string(chatID);
            int64_t expiration = subs[userIDStr];

            auto expirationTime = chrono::system_clock::from_time_t(expiration);
            time_t tt = chrono::system_clock::to_time_t(expirationTime);
            stringstream ss;
            ss << put_time(localtime(&tt), "%Y/%m/%d");
            string expirationDate = ss.str();

            string timeStr = FormatTimeRemaining(timeRemaining);
            string responseText = "Welcome To Hex Service Bot, Your Subscribe ends in " + expirationDate + "\n\nTime remaining: " + timeStr + "\n\nEnjoy!";
            SendTelegramMessage(chatID, responseText);
        }
    } else {
        string responseText = "You are not subscribed. Contact " + CONTACT_USERNAME + " to subscribe.";
        SendTelegramMessage(chatID, responseText);
    }
}

void HandleEnterKey(int64_t chatID) {
    SendTelegramMessage(chatID, "Please enter your key:");
    userStates[chatID] = "waiting_key";
}

void HandleAdminCommands(int64_t chatID, const string& text) {
    if (!IsAdmin(chatID)) {
        return;
    }

    vector<string> parts;
    boost::split(parts, text, boost::is_any_of(" "));

    if (parts[0] == "/addsub" && parts.size() == 3) {
        int64_t userID = stoll(parts[1]);
        int days = stoi(parts[2]);

        if (AddSubscriber(userID, days)) {
            SendTelegramMessage(chatID, "Added user " + to_string(userID) + " with " + to_string(days) + " days subscription");
        } else {
            SendTelegramMessage(chatID, "Failed to add subscriber");
        }
    } else if (parts[0] == "/ckey" && parts.size() == 2) {
        string timeStr = parts[1];
        auto [durationSeconds, valid] = ParseTimeFormat(timeStr);
        
        if (!valid) {
            SendTelegramMessage(chatID, "Invalid time format. Examples: 7d, 30m, 24h, 2w");
            return;
        }

        string keyCode = GenerateKey();
        int64_t now = chrono::duration_cast<chrono::seconds>(chrono::system_clock::now().time_since_epoch()).count();
        int64_t expirationTime = now + durationSeconds;

        auto keys = LoadKeys();
        keys[keyCode] = expirationTime;
        
        if (SaveKeys(keys)) {
            auto expirationTimePoint = chrono::system_clock::from_time_t(expirationTime);
            time_t tt = chrono::system_clock::to_time_t(expirationTimePoint);
            stringstream ss;
            ss << put_time(localtime(&tt), "%Y/%m/%d %H:%M:%S");
            
            string responseText = "Key generated successfully!\n\nDuration: " + timeStr + 
                                "\nExpires: " + ss.str() + "\n\nKey:\n" + keyCode + "\n\nTap to copy the key above";
            SendTelegramMessage(chatID, responseText);
        } else {
            SendTelegramMessage(chatID, "Failed to save key");
        }
    } else if (parts[0] == "/removesub" && parts.size() == 2) {
        int64_t userID = stoll(parts[1]);
        
        if (RemoveSubscriber(userID)) {
            SendTelegramMessage(chatID, "Removed user " + to_string(userID) + " from subscribers");
        } else {
            SendTelegramMessage(chatID, "Failed to remove subscriber");
        }
    } else if (text == "/subcount") {
        int count = GetSubscriberCount();
        SendTelegramMessage(chatID, "Total active subscribers: " + to_string(count));
    } else if (parts[0] == "/cpubkey" && parts.size() == 2) {
        string timeStr = parts[1];
        auto [durationSeconds, valid] = ParseTimeFormat(timeStr);
        
        if (!valid) {
            SendTelegramMessage(chatID, "Invalid time format. Examples: 7d, 30m, 24h, 2w");
            return;
        }

        string keyCode = GenerateKey();
        int64_t now = chrono::duration_cast<chrono::seconds>(chrono::system_clock::now().time_since_epoch()).count();
        int64_t expirationTime = now + durationSeconds;

        auto keys = LoadPublicKeys();
        keys[keyCode] = expirationTime;
        
        if (SavePublicKeys(keys)) {
            auto expirationTimePoint = chrono::system_clock::from_time_t(expirationTime);
            time_t tt = chrono::system_clock::to_time_t(expirationTimePoint);
            stringstream ss;
            ss << put_time(localtime(&tt), "%Y/%m/%d %H:%M:%S");
            
            string responseText = "Public trial key generated successfully!\n\nDuration: " + timeStr + 
                                "\nExpires: " + ss.str() + "\n\nKey:\n" + keyCode + 
                                "\n\nThis key can be used by unlimited users during the trial period.";
            SendTelegramMessage(chatID, responseText);
        } else {
            SendTelegramMessage(chatID, "Failed to save public key");
        }
    } else if (text == "/help_admin") {
        string helpText = "Admin Commands:\n\n"
                         "User Management:\n"
                         "/addsub <user_id> <days> - Add subscription to a user\n"
                         "/removesub <user_id> - Remove user subscription\n"
                         "/subcount - Show total active subscribers\n\n"
                         "Key Management:\n"
                         "/ckey <time> - Create regular key (single use)\n"
                         "/cpubkey <time> - Create public trial key (unlimited use)\n\n"
                         "Time Format Examples:\n"
                         "• 7d (7 days)\n"
                         "• 24h (24 hours)\n"
                         "• 30m (30 minutes)\n"
                         "• 2w (2 weeks)\n\n"
                         "Examples:\n"
                         "/addsub 123456789 30\n"
                         "/ckey 7d\n"
                         "/cpubkey 24h";
        SendTelegramMessage(chatID, helpText);
    }
}

void ProcessTelegramUpdate(const json& update) {
    if (!update.contains("message")) {
        return;
    }

    auto message = update["message"];
    int64_t chatID = message["chat"]["id"];
    string text = message.contains("text") ? message["text"] : "";
    int64_t userID = message["from"]["id"];

    if (text.substr(0, 1) == "/") {
        if (text == "/start") {
            HandleStart(chatID);
            return;
        }
        
        HandleAdminCommands(chatID, text);
        return;
    }

    if (text == "Cancel") {
        userStates.erase(chatID);
        SendTelegramMessage(chatID, "Operation cancelled.");
        return;
    }

    set<string> allowedWithoutSubscription = {"Check Subscription", "Enter Key"};
    
    auto stateIt = userStates.find(chatID);
    if (stateIt != userStates.end() && stateIt->second == "waiting_key") {
        HandleKeyInput(chatID, text);
        return;
    }

    if (!IsAdmin(userID) && allowedWithoutSubscription.find(text) == allowedWithoutSubscription.end() && !RequireSubscription(chatID)) {
        return;
    }

    if (stateIt != userStates.end()) {
        string state = stateIt->second;
        if (state == "waiting_session") {
            HandleSessionInput(chatID, text);
            return;
        }
    }

    if (text == "Check Subscription") {
        HandleCheckSubscription(chatID);
    } else if (text == "Enter Key") {
        HandleEnterKey(chatID);
    } else if (text == "Login using Session ID") {
        userStates[chatID] = "waiting_session";
        SendTelegramMessage(chatID, "Please send your Instagram session ID:");
    } else if (text == "Login username:pass") {
        userStates[chatID] = "waiting_username";
        SendTelegramMessage(chatID, "Please send your username:");
    } else if (text == "Log out") {
        lock_guard<mutex> lock(dataMutex);
        if (userData[chatID] != nullptr) {
            delete userData[chatID];
            userData.erase(chatID);
        }
        userStates.erase(chatID);
        SendTelegramMessage(chatID, "Successfully logged out!");
    }
}

void GetTelegramUpdates() {
    int64_t lastUpdateId = 0;
    
    while (true) {
        string url = "https://api.telegram.org/bot" + BOT_TOKEN + "/getUpdates?offset=" + to_string(lastUpdateId + 1) + "&timeout=60";
        
        try {
            string response = HttpGet(url);
            if (response.empty()) {
                this_thread::sleep_for(chrono::seconds(1));
                continue;
            }

            json j = json::parse(response);
            if (j["ok"] && j.contains("result")) {
                for (const auto& update : j["result"]) {
                    lastUpdateId = update["update_id"];
                    ProcessTelegramUpdate(update);
                }
            }
        } catch (const exception& e) {
            cerr << "Error processing updates: " << e.what() << endl;
            this_thread::sleep_for(chrono::seconds(5));
        }
    }
}

int main() {
    curl_global_init(CURL_GLOBAL_DEFAULT);
    
    cout << "Hex Bot started..." << endl;
    
    GetTelegramUpdates();
    
    for (auto& pair : userData) {
        delete pair.second;
    }
    
    curl_global_cleanup();
    return 0;
}