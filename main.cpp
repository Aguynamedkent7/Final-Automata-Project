#include <iostream>
#include <vector>
#include <string>
#include <limits> 
#include <fstream>
#include <iomanip>
#include "Packet.h"
#include "StatelessDFA.h"
#include "SessionPDA.h"

using namespace std;

// --- SCENARIO GENERATORS ---

// 1. Malicious Payload (Signature: "root")
vector<Packet> createScenario_MaliciousContent() {
    vector<Packet> traffic;
    traffic.push_back({"1.2.3.4", "10.0.0.1", SYN, ""});
    traffic.push_back({"1.2.3.4", "10.0.0.1", ACK, ""});
    traffic.push_back({"1.2.3.4", "10.0.0.1", 0, "I want root access"}); 
    return traffic;
}

// 2. Out of Order (Protocol Violation)
vector<Packet> createScenario_OutOfOrder() {
    vector<Packet> traffic;
    traffic.push_back({"1.2.3.4", "10.0.0.1", 0, "Hello Server"}); 
    return traffic;
}

// 3. Buffer Overflow (Signature: \x90 NOP Sled)
vector<Packet> createScenario_BufferOverflow() {
    vector<Packet> traffic;
    traffic.push_back({"6.6.6.6", "10.0.0.1", SYN, ""});
    traffic.push_back({"6.6.6.6", "10.0.0.1", ACK, ""});
    string exploitPayload = "\x90\x90\x90\x90\x90"; 
    exploitPayload += "\xCC\xCC"; 
    traffic.push_back({"6.6.6.6", "10.0.0.1", 0, exploitPayload});
    return traffic;
}

// 4. Valid HTTP Request (Safe)
vector<Packet> createScenario_ValidHTTP() {
    vector<Packet> traffic;
    traffic.push_back({"192.168.1.5", "10.0.0.1", SYN, ""});
    traffic.push_back({"192.168.1.5", "10.0.0.1", ACK, ""});
    traffic.push_back({"192.168.1.5", "10.0.0.1", 0, "GET /index.html HTTP/1.1"});
    return traffic;
}

// 5. SQL Injection (Passes DFA because "root" is missing - demonstrates limitation)
vector<Packet> createScenario_SQLInjection() {
    vector<Packet> traffic;
    traffic.push_back({"192.168.1.5", "10.0.0.1", SYN, ""});
    traffic.push_back({"192.168.1.5", "10.0.0.1", ACK, ""});
    traffic.push_back({"192.168.1.5", "10.0.0.1", 0, "SELECT * FROM users WHERE admin=1"});
    return traffic;
}

// 6. XSS Attack (Blocked because payload contains "root")
vector<Packet> createScenario_XSS() {
    vector<Packet> traffic;
    traffic.push_back({"10.10.10.10", "10.0.0.1", SYN, ""});
    traffic.push_back({"10.10.10.10", "10.0.0.1", ACK, ""});
    traffic.push_back({"10.10.10.10", "10.0.0.1", 0, "<script>var user='root';</script>"});
    return traffic;
}

// --- WEB INTEGRATION ---
void exportToWeb(const vector<vector<Packet>>& allScenarios) {
    ofstream out("simulation_data.js");
    if (!out) {
        cerr << "Error: Could not write web data file.\n";
        return;
    }

    out << "const cppData = {\n";
    for(size_t i = 0; i < allScenarios.size(); ++i) {
        out << "  scenario" << (i + 1) << ": [\n";
        for (size_t j = 0; j < allScenarios[i].size(); ++j) {
            const Packet& p = allScenarios[i][j];
            out << "    { flags: '";
            if (p.flags & SYN) out << "S";
            else if (p.flags & ACK) out << "A";
            else if (p.flags & FIN) out << "F";
            else if (p.flags & RST) out << "R";
            out << "', payload: \"";
            
            for (unsigned char c : p.payload) {
                if (c == '"') out << "\\\"";
                else if (c == '\\') out << "\\\\";
                else if (c >= 32 && c <= 126) out << c;
                else out << "\\x" << hex << setw(2) << setfill('0') << (int)c << dec;
            }
            out << "\" }";
            if (j < allScenarios[i].size() - 1) out << ",";
            out << "\n";
        }
        out << "  ],\n";
    }
    out << "};\n";
    out.close();

    cout << ">>> Data exported to simulation_data.js\n";
    cout << ">>> Launching HTML Visualizer...\n";
    
    #ifdef _WIN32
        system("start html_visualizer.html");
    #elif __APPLE__
        system("open html_visualizer.html");
    #else
        system("xdg-open html_visualizer.html");
    #endif
}

void waitUser() {
    cout << "\n[PRESS ENTER FOR NEXT SCENARIO]...";
    cin.ignore(numeric_limits<streamsize>::max(), '\n'); 
    cout << "\n";
}

int main() {
    // Collect all scenarios
    vector<vector<Packet>> scenarios;
    scenarios.push_back(createScenario_MaliciousContent());
    scenarios.push_back(createScenario_OutOfOrder());
    scenarios.push_back(createScenario_BufferOverflow());
    scenarios.push_back(createScenario_ValidHTTP());
    scenarios.push_back(createScenario_SQLInjection());
    scenarios.push_back(createScenario_XSS());

    cout << "==============================================================\n";
    cout << " NETWORK SECURITY AUTOMATA SIMULATOR\n";
    cout << " Generating Scenarios & Exporting to Web...\n";
    cout << "==============================================================\n";
    
    exportToWeb(scenarios);

    cout << "Browser launched. You can also review scenarios here in the console.\n";
    waitUser();

    StatelessDFA dfa;
    
    // Console Loop (Optional, for debugging)
    for(size_t i = 0; i < scenarios.size(); ++i) {
        cout << "\n=== CONSOLE SCENARIO " << (i+1) << " ===\n";
        SessionPDA pda("CLIENT", "SERVER");
        
        for(const auto& pkt : scenarios[i]) {
            pkt.print();
            bool dfaSafe = dfa.processPacket(pkt);
            bool pdaSafe = pda.processPacket(pkt);
            
            if(!dfaSafe) cout << ">>> [BLOCKED] DFA Signature Match\n";
            if(!pdaSafe) cout << ">>> [BLOCKED] PDA Protocol Violation\n";
            if(dfaSafe && pdaSafe) cout << ">>> [ALLOWED] Packet Safe\n";
            cout << "---\n";
        }
        waitUser();
    }

    return 0;
}