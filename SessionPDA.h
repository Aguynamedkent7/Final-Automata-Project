#pragma once
#include "Packet.h"
#include <iostream>
#include <string>
#include <stack>
#include <thread> // For animation sleep
#include <chrono> // For time units

using namespace std;

// The symbols we push onto the stack
enum StackSymbol {
    WAITING_FOR_ACK,
    SESSION_ACTIVE
};

// Define states for the PDA
enum class ConnectionState {
    CLOSED,
    SYN_SENT,
    ESTABLISHED
};

class SessionPDA {
private:
    stack<StackSymbol> protocolStack;
    ConnectionState currentState;
    string clientIP;
    string serverIP;

    // --- VISUALIZATION HELPERS ---
    
    // Returns a string representation of the stack's top element
    string getStackVisual() const {
        if (protocolStack.empty()) return "[ EMPTY ]";
        if (protocolStack.top() == WAITING_FOR_ACK) return "[ WAIT_ACK ]";
        if (protocolStack.top() == SESSION_ACTIVE) return "[ ACTIVE_SES ]";
        return "[ ? ]";
    }

    // Draws the PDA "Dashboard"
    void drawDashboard(string actionMessage, bool success = true) const {
        // ANSI Colors
        string CYAN = "\033[1;36m";
        string GREEN = "\033[1;32m";
        string RED = "\033[1;31m";
        string YELLOW = "\033[1;33m";
        string RESET = "\033[0m";
        string DIM = "\033[90m";

        string stateColor = (success) ? CYAN : RED;
        
        // 1. Clear line to create animation frame
        cout << "\r" << string(100, ' ') << "\r"; 

        // 2. Draw State Machine
        cout << "PDA STATE: ";
        if (currentState == ConnectionState::CLOSED) cout << GREEN << "(CLOSED)" << RESET;
        else cout << DIM << "(CLOSED)" << RESET;
        cout << " -> ";
        if (currentState == ConnectionState::SYN_SENT) cout << YELLOW << "(SYN_SENT)" << RESET;
        else cout << DIM << "(SYN_SENT)" << RESET;
        cout << " -> ";
        if (currentState == ConnectionState::ESTABLISHED) cout << CYAN << "(ESTAB)" << RESET;
        else cout << DIM << "(ESTAB)" << RESET;

        // 3. Draw Stack
        cout << "  ||  STACK: " << YELLOW << getStackVisual() << RESET;

        // 4. Draw Action Message
        cout << "  ||  ACTION: " << actionMessage << flush;
    }

   void animateDelay() const {
        // Slowed down to 2 seconds per logical step
        std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    }

public:
    SessionPDA(const string& client, const string& server)
        : currentState(ConnectionState::CLOSED), clientIP(client), serverIP(server) {}

    bool processPacket(const Packet& pkt) {
        cout << "\n[PDA Analysis] Processing Flags: " << pkt.flags << "\n";

        // Initial Draw
        drawDashboard("Analyzing Packet...", true);
        animateDelay();

        // 1. Handle SYN (Start of Handshake)
        if (pkt.flags & SYN) {
            if (!protocolStack.empty()) {
                drawDashboard("REJECT: Double SYN", false);
                cout << "\n";
                return false;
            }
            
            // Animation: State Change
            currentState = ConnectionState::SYN_SENT;
            drawDashboard("SYN Recv -> State Change", true);
            animateDelay();

            // Animation: Push to Stack
            protocolStack.push(WAITING_FOR_ACK);
            drawDashboard("PUSHING 'WAIT_ACK'", true);
            animateDelay();

            cout << "\n\033[1;32m>>> HANDSHAKE STARTED <<<\033[0m\n";
            return true;
        }

        // 2. Handle ACK (Completion of Handshake)
        if (pkt.flags & ACK) {
            // Check Stack (The Context-Free Part)
            if (protocolStack.empty()) {
                drawDashboard("REJECT: Stack Empty (No SYN)", false);
                cout << "\n\033[1;31m>>> REJECTED: ACK Scan Detected <<<\033[0m\n";
                return false;
            }
            
            if (protocolStack.top() == WAITING_FOR_ACK) {
                // Pop Expectation
                protocolStack.pop();
                drawDashboard("POPPING 'WAIT_ACK'", true);
                animateDelay();

                // Push Active Session
                protocolStack.push(SESSION_ACTIVE);
                currentState = ConnectionState::ESTABLISHED; // Update state
                drawDashboard("PUSH 'ACTIVE' & STATE -> ESTAB", true);
                animateDelay();

                cout << "\n\033[1;32m>>> CONNECTION ESTABLISHED <<<\033[0m\n";
                return true;
            }
        }

        // 3. Handle Data Payload (Needs Active Session)
        if (!pkt.payload.empty()) {
            if (protocolStack.empty() || protocolStack.top() != SESSION_ACTIVE) {
                 drawDashboard("REJECT: No Session on Stack", false);
                 cout << "\n\033[1;31m>>> REJECTED: Data without Handshake <<<\033[0m\n";
                 return false;
            }
            drawDashboard("PASS: Session Valid", true);
            cout << "\n\033[1;32m>>> DATA ACCEPTED <<<\033[0m\n";
            return true;
        }

        cout << "\n"; // Clean exit
        return false;
    }
};