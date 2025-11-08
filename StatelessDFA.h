#pragma once
#include "Packet.h"
#include <string>
#include <vector>
#include <iostream>

using namespace std;

class StatelessDFA {
private:
    vector<string> maliciousSignatures;

public:
    StatelessDFA() {
        maliciousSignatures.push_back("/etc/shadow");
        maliciousSignatures.push_back("nmap-scan");
    }

    bool processPacket(const Packet& pkt) const {
        cout << "[DFA] ";

        if ((pkt.flags & SYN) && (pkt.flags & FIN)) {
            cout << "Packet REJECTED (SYN+FIN flags).\n";
            return false;
        }

        for (const string& signature : maliciousSignatures) {
            if (pkt.payload.find(signature) != string::npos) {
                cout << "Packet REJECTED (Payload signature match).\n";
                return false;
            }
        }

        cout << "Packet ACCEPTED.\n";
        return true;
    }
};