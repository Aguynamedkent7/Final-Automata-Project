#pragma once
#include "Packet.h"
#include <iostream>
#include <string>

using namespace std;

enum class ConnectionState {
    CLOSED,
    SYN_SENT,
    ESTABLISHED,
    FIN_WAIT
};

class SessionPDA {
private:
    ConnectionState currentState;
    string clientIP;
    string serverIP;

public:
    SessionPDA(const string& client, const string& server)
        : currentState(ConnectionState::CLOSED), clientIP(client), serverIP(server) {}

    bool processPacket(const Packet& pkt) {
        cout << "[PDA] Current State: " << stateToString(currentState) << ". ";
        
        switch (currentState) {
            case ConnectionState::CLOSED:
                if ((pkt.flags & SYN) && pkt.sourceIP == clientIP) {
                    currentState = ConnectionState::SYN_SENT;
                    cout << "-> SYN_SENT. Packet ACCEPTED.\n";
                    return true;
                }
                break;

            case ConnectionState::SYN_SENT:
                if ((pkt.flags & ACK) && pkt.sourceIP == clientIP) {
                    currentState = ConnectionState::ESTABLISHED;
                    cout << "-> ESTABLISHED. Packet ACCEPTED.\n";
                    return true;
                }
                break;

            case ConnectionState::ESTABLISHED:
                if (!pkt.payload.empty() || (pkt.flags & FIN)) {
                    cout << "Data/FIN packet. Packet ACCEPTED.\n";
                    return true;
                }
                break;
        }

        cout << "Packet REJECTED (Invalid State).\n";
        return false;
    }

    string stateToString(ConnectionState state) {
        switch (state) {
            case ConnectionState::CLOSED: return "CLOSED";
            case ConnectionState::SYN_SENT: return "SYN_SENT";
            case ConnectionState::ESTABLISHED: return "ESTABLISHED";
            case ConnectionState::FIN_WAIT: return "FIN_WAIT";
            default: return "UNKNOWN";
        }
    }
};