#include <iostream>
#include <vector>
#include <string>
#include <limits> // Required for clearing input buffer
#include "Packet.h"
#include "StatelessDFA.h"
#include "SessionPDA.h"

using namespace std;

// --- Helper: Pauses the console until Enter is pressed ---
void waitUser() {
    cout << "\n[PRESS ENTER TO PROCESS NEXT PACKET]...";
    cin.ignore(numeric_limits<streamsize>::max(), '\n'); // Wait for input
    cout << "\n";
}

vector<Packet> createScenario_BufferOverflow() {
    vector<Packet> traffic;
    // 1. Valid Handshake
    traffic.push_back({"6.6.6.6", "10.0.0.1", SYN, ""});
    traffic.push_back({"6.6.6.6", "10.0.0.1", ACK, ""});
    
    // 2. The Exploit Packet
    // We construct a string containing NOPs (\x90) followed by "shellcode"
    string exploitPayload = "\x90\x90\x90\x90\x90"; // 5 NOPs
    exploitPayload += "\xCC\xCC"; // INT 3 (Debug Interrupt - fake shellcode)
    
    traffic.push_back({"6.6.6.6", "10.0.0.1", 0, exploitPayload});
    return traffic;
}

// --- Helper functions to create scenarios ---
vector<Packet> createScenario_MaliciousContent() {
    vector<Packet> traffic;
    traffic.push_back({"1.2.3.4", "10.0.0.1", SYN, ""});
    traffic.push_back({"1.2.3.4", "10.0.0.1", ACK, ""});
    traffic.push_back({"1.2.3.4", "10.0.0.1", 0, "I want root access"}); 
    return traffic;
}

vector<Packet> createScenario_OutOfOrder() {
    vector<Packet> traffic;
    traffic.push_back({"1.2.3.4", "10.0.0.1", 0, "Hello Server"}); 
    return traffic;
}

int main() {
    StatelessDFA dfa;
    
    cout << "==============================================================\n";
    cout << " NETWORK SECURITY AUTOMATA SIMULATOR\n";
    cout << " Press Enter to step through the simulation packet-by-packet.\n";
    cout << "==============================================================\n";
    cin.get(); // Initial wait

    // --- TEST 1 ---
    cout << "\n=== SCENARIO 1: Malicious Payload (DFA Test) ===\n";
    cout << "Goal: Demonstrate Type-3 Regular Language detection.\n";
    
    SessionPDA pda1("1.2.3.4", "10.0.0.1");
    for (const auto& pkt : createScenario_MaliciousContent()) {
        pkt.print();
        
        cout << "Running DFA Check...\n";
        bool dfaSafe = dfa.processPacket(pkt);
        
        cout << "Running PDA Check...\n";
        bool pdaSafe = pda1.processPacket(pkt);
        
        if (!dfaSafe) cout << ">>> RESULT: BLOCKED BY DFA (Signature)\n";
        if (!pdaSafe) cout << ">>> RESULT: BLOCKED BY PDA (Protocol)\n";
        
        cout << "------------------------------------------------\n";
        waitUser(); // <--- PAUSE HERE
    }

    // --- TEST 2 ---
    cout << "\n=== SCENARIO 2: Out of Order Data (PDA Test) ===\n";
    cout << "Goal: Demonstrate Type-2 Context-Free Grammar validation.\n";

    SessionPDA pda2("1.2.3.4", "10.0.0.1");
    for (const auto& pkt : createScenario_OutOfOrder()) {
        pkt.print();

        cout << "Running DFA Check...\n";
        bool dfaSafe = dfa.processPacket(pkt); // Will pass (no bad words)

        cout << "Running PDA Check...\n";
        bool pdaSafe = pda2.processPacket(pkt); // Will fail (stack empty)

        if (!dfaSafe) cout << ">>> RESULT: BLOCKED BY DFA (Signature)\n";
        else cout << ">>> INFO: DFA passed this packet (No malicious words).\n";

        if (!pdaSafe) cout << ">>> RESULT: BLOCKED BY PDA (Invalid Handshake Sequence)\n";
        
        cout << "------------------------------------------------\n";
        waitUser(); // <--- PAUSE HERE
    }

    // --- TEST 3 ---
    cout << "\n=== SCENARIO 3: Binary Exploit Detection (NOP Sled) ===\n";
    cout << "Goal: Demonstrate detection of non-printable binary signatures (0x90).\n";

    SessionPDA pda3("6.6.6.6", "10.0.0.1");
    for (const auto& pkt : createScenario_BufferOverflow()) {
        pkt.print();

        cout << "Running DFA Check...\n";
        bool dfaSafe = dfa.processPacket(pkt);

        cout << "Running PDA Check...\n";
        bool pdaSafe = pda3.processPacket(pkt); // This will pass (valid session)

        if (!dfaSafe) cout << ">>> RESULT: BLOCKED BY DFA (Binary Signature)\n";
        else cout << ">>> RESULT: DFA Passed.\n";

        if (!pdaSafe) cout << ">>> RESULT: BLOCKED BY PDA (Protocol)\n";
        
        cout << "------------------------------------------------\n";
        waitUser();
    }

    return 0;
}