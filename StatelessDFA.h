#pragma once
#include "Packet.h"
#include <string>
#include <vector>
#include <iostream>
#include <thread> 
#include <chrono> 

using namespace std;

class StatelessDFA {
private:
    
    void drawVisualDFA(int activeState, unsigned char inputChar) const { 
        cout << "\r"; 
        
        string RESET = "\033[0m";
        string GREEN = "\033[1;32m";
        string DIM = "\033[90m";

        auto color = [&](int stateID) { return (stateID == activeState) ? GREEN : DIM; };

        
        string charDisplay;
        if (inputChar >= 32 && inputChar <= 126) {
            charDisplay = string(1, inputChar); 
        } else {
            charDisplay = "\\x" + to_string((int)inputChar); 
        }

        cout << "Scanning '" << charDisplay << "':  ";
        
        
        cout << color(0) << "(S)" << RESET << "-r-" 
             << color(1) << "(r)" << RESET << "-o-" 
             << color(2) << "(ro)" << RESET << "-o-" 
             << color(3) << "(roo)" << RESET << "-t-" 
             << color(4) << "[TRAP]" << RESET;

        cout << "  ||  ";

       
        cout << color(5) << "(\\x90)" << RESET << "--" 
             << color(6) << "(x2)" << RESET << "--" 
             << color(7) << "[SHELLCODE]" << RESET;
        
        cout << flush;
    }

public:
    bool processPacket(const Packet& pkt) const {
        cout << "\n[DFA Analysis] Payload Size: " << pkt.payload.size() << " bytes\n";

        if (pkt.payload.empty()) {
            cout << "No payload to scan.\n";
            return true;
        }

        int state = 0;
        
       
        for (unsigned char c : pkt.payload) {
            
            drawVisualDFA(state, c);
            std::this_thread::sleep_for(std::chrono::milliseconds(1000)); 
            switch (state) {
                case 0: 
                    if (c == 'r') state = 1;
                    else if (c == 0x90) state = 5; 
                    else state = 0; 
                    break;

                // --- PATH 1: "root" ---
                case 1: state = (c == 'o') ? 2 : (c == 'r' ? 1 : 0); break;
                case 2: state = (c == 'o') ? 3 : (c == 'r' ? 1 : 0); break;
                case 3: state = (c == 't') ? 4 : (c == 'r' ? 1 : 0); break;
                case 4: break; // Trap for "root"

                // --- PATH 2: NOP Sled (\x90\x90\x90) ---
                case 5: 
                    if (c == 0x90) state = 6;
                    else if (c == 'r') state = 1; 
                    else state = 0; 
                    break;
                case 6: 
                    if (c == 0x90) state = 7; 
                    else if (c == 'r') state = 1; 
                    else state = 0; 
                    break;
                case 7: break; 
            }
        }
        
        cout << endl;

        if (state == 4) {
            cout << "\033[1;31m>>> REJECT: Text Signature 'root' Detected <<<\033[0m\n";
            return false;
        }
        if (state == 7) {
            cout << "\033[1;31m>>> REJECT: Binary Signature 'NOP Sled' Detected (Buffer Overflow Attempt) <<<\033[0m\n";
            return false;
        }

        cout << "\033[1;32m>>> PAYLOAD CLEAN <<<\033[0m\n";
        return true;
    }
};