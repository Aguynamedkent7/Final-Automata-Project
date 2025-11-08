#pragma once
#include <string>
#include <iostream>

using namespace std;

enum Flags {
    SYN = 1 << 0,
    ACK = 1 << 1,
    FIN = 1 << 2,
    RST = 1 << 3,
};

struct Packet {
    string sourceIP;
    string destIP;
    int flags;
    string payload;

    void print() const {
        cout << "\t" << sourceIP << " -> " << destIP
             << " Flags: " << (flags & SYN ? "S" : "")
             << (flags & ACK ? "A" : "")
             << (flags & FIN ? "F" : "")
             << (flags & RST ? "R" : "")
             << " Payload: \"" << payload << "\"\n";
    }
};