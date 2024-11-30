#include <winsock2.h>
#include <ws2tcpip.h>
#include <time.h>

#pragma comment(lib, "ws2_32.lib")

int main() {
    // Seed
    srand((unsigned int)time(NULL));

    const char *serverIpAddresses[] = {
        "8.8.8.8",
        "142.250.190.78"
    };
    int noOfIpAddresses = sizeof(serverIpAddresses) / sizeof(serverIpAddresses[0]);
    const int serverPort = 80;

    WSADATA wsaData;
    SOCKET clientSocket;
    struct sockaddr_in serverAddr;

    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return 1;
    }

    // Create socket
    clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (clientSocket == INVALID_SOCKET) {
        WSACleanup();
        return 1;
    }

    // Get random IP address
    int randomIndex = rand() % noOfIpAddresses;
    const char *serverIP = serverIpAddresses[randomIndex];

    // Configure server address
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(serverPort);
    inet_pton(AF_INET, serverIP, &serverAddr.sin_addr);

    // Connect to server
    if (connect(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        closesocket(clientSocket);
        WSACleanup();
        return 1;
    }

    // Keep-alive loop
    const char *keepAliveMessage = "KEEP_ALIVE";

    while (1) {
        // Send keep-alive message
        int sendResult = send(clientSocket, keepAliveMessage, (int)strlen(keepAliveMessage), 0);
        if (sendResult == SOCKET_ERROR) {
            break;
        }
        Sleep(5000);
    }

    // Close socket and cleanup
    closesocket(clientSocket);
    WSACleanup();

    return 0;
}
