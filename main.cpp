#include <iostream>
#include <vector>
#include <string>
#include "Packet.h"
#include "StatelessDFA.h"
#include "SessionPDA.h"

using namespace std;

// --- Helper functions to create scenarios ---
vector<Packet> createScenario_AckScan() {
    vector<Packet> traffic;
    traffic.push_back({"1.2.3.4", "10.0.0.1", ACK, ""});
    return traffic;
}

vector<Packet> createScenario_MaliciousPayload() {
    vector<Packet> traffic;
    traffic.push_back({"1.2.3.4", "10.0.0.1", SYN, ""});
    traffic.push_back({"1.2.3.4", "10.0.0.1", ACK, ""});
    traffic.push_back({"1.2.3.4", "10.0.0.1", ACK, "GET /etc/shadow"});
    return traffic;
}

// --- Main Simulation ---
int main() {
    StatelessDFA dfa;
    SessionPDA pda("1.2.3.4", "10.0.0.1");

    cout << "--- SCENARIO 1: ACK SCAN ---\n";
    for (const auto& pkt : createScenario_AckScan()) {
        pkt.print();
        bool dfa_result = dfa.processPacket(pkt);
        bool pda_result = pda.processPacket(pkt);
        cout << "----------------------------\n";
    }
    
    // Reset PDA for next scenario
    pda = SessionPDA("1.2.3.4", "10.0.0.1"); 
    
    cout << "\n--- SCENARIO 2: MALICIOUS PAYLOAD ---\n";
    for (const auto& pkt : createScenario_MaliciousPayload()) {
        pkt.print();
        bool dfa_result = dfa.processPacket(pkt);
        bool pda_result = pda.processPacket(pkt);
        cout << "----------------------------\n";
    }

    return 0;
}