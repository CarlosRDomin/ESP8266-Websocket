//#define DEBUGGING

//MS:

#include "global.h"
#include "WebSocketClient.h"

#include "sha1.h"
#include "Base64.h"


bool WebSocketClient::handshake(Client &client) {

    socket_client = &client;

    // If there is a connected client->
    if (socket_client->connected()) {
        // Check request and look for websocket handshake
#ifdef DEBUGGING
            Serial.println(F("Client connected"));
#endif
        if (analyzeRequest()) {
#ifdef DEBUGGING
                Serial.println(F("Websocket established"));
#endif

                return true;

        } else {
            // Might just need to break until out of socket_client loop.
#ifdef DEBUGGING
            Serial.println(F("Invalid handshake"));
#endif
            disconnectStream();

            return false;
        }
    } else {
        return false;
    }
}

bool WebSocketClient::analyzeRequest() {
    String temp;

    int bite;
    bool foundupgrade = false;
    unsigned long intkey[2];
    String serverKey;
    char keyStart[17];
    char b64Key[25];
    String key = "------------------------";

    randomSeed(analogRead(0));

    for (int i=0; i<16; ++i) {
        keyStart[i] = (char)random(1, 256);
    }

    base64_encode(b64Key, keyStart, 16);

    for (int i=0; i<24; ++i) {
        key[i] = b64Key[i];
    }

#ifdef DEBUGGING
    Serial.println(F("Sending websocket upgrade headers"));
#endif

    socket_client->print(F("GET "));
    socket_client->print(path);
    socket_client->print(F(" HTTP/1.1\r\n"));
    socket_client->print(F("Upgrade: websocket\r\n"));
    socket_client->print(F("Connection: Upgrade\r\n"));
    socket_client->print(F("Host: "));
    socket_client->print(host);
    socket_client->print(CRLF);
    socket_client->print(F("Sec-WebSocket-Key: "));
    socket_client->print(key);
    socket_client->print(CRLF);
    socket_client->print(F("Sec-WebSocket-Protocol: "));
    socket_client->print(protocol);
    socket_client->print(CRLF);
    socket_client->print(F("Sec-WebSocket-Version: 13\r\n"));
    socket_client->print(CRLF);

#ifdef DEBUGGING
    Serial.println(F("Analyzing response headers"));
#endif

    while (socket_client->connected() && !socket_client->available()) {
        delay(100);
        Serial.println("Waiting...");
    }

    // TODO: More robust string extraction
    while ((bite = socket_client->read()) != -1) {

        temp += (char)bite;

        if ((char)bite == '\n') {
#ifdef DEBUGGING
            Serial.print("Got Header: " + temp);
#endif
            if (!foundupgrade && temp.startsWith("Upgrade: websocket")) {
                foundupgrade = true;
            } else if (temp.startsWith("Sec-WebSocket-Accept: ")) {
                serverKey = temp.substring(22,temp.length() - 2); // Don't save last CR+LF
            }
            temp = "";
        }

        if (!socket_client->available()) {
          delay(20);
        }
    }

    key += "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    uint8_t *hash;
    char result[21];
    char b64Result[30];

    SHA1Context sha;
    int err;
    uint8_t Message_Digest[20];

    err = SHA1Reset(&sha);
    err = SHA1Input(&sha, reinterpret_cast<const uint8_t *>(key.c_str()), key.length());
    err = SHA1Result(&sha, Message_Digest);
    hash = Message_Digest;

    for (int i=0; i<20; ++i) {
        result[i] = (char)hash[i];
    }
    result[20] = '\0';

    base64_encode(b64Result, result, 20);

    // if the keys match, good to go
    return serverKey.equals(String(b64Result));
}


bool WebSocketClient::handleStream(String& data, uint8_t *opcode) {
    uint8_t msgtype;
    uint8_t bite;
    unsigned int length;
    uint8_t mask[4];
    uint8_t index;
    unsigned int i;
    bool hasMask = false;

    if (!socket_client->connected() || !socket_client->available())
    {
        return false;
    }

    msgtype = timedRead();
    if (!socket_client->connected()) {
        return false;
    }

    length = timedRead();

    if (length & WS_MASK) {
        hasMask = true;
        length = length & ~WS_MASK;
    }


    if (!socket_client->connected()) {
        return false;
    }

    index = 6;

    if (length == WS_SIZE16) {
        length = timedRead() << 8;
        if (!socket_client->connected()) {
            return false;
        }

        length |= timedRead();
        if (!socket_client->connected()) {
            return false;
        }

    } else if (length == WS_SIZE64) {
#ifdef DEBUGGING
        Serial.println(F("No support for over 16 bit sized messages"));
#endif
        return false;
    }

    if (hasMask) {
        // get the mask
        mask[0] = timedRead();
        if (!socket_client->connected()) {
            return false;
        }

        mask[1] = timedRead();
        if (!socket_client->connected()) {

            return false;
        }

        mask[2] = timedRead();
        if (!socket_client->connected()) {
            return false;
        }

        mask[3] = timedRead();
        if (!socket_client->connected()) {
            return false;
        }
    }

    data = "";

    if (opcode != NULL)
    {
      *opcode = msgtype & ~WS_FIN;
    }

    if (hasMask) {
        for (i=0; i<length; ++i) {
            data += (char) (timedRead() ^ mask[i % 4]);
            if (!socket_client->connected()) {
                return false;
            }
        }
    } else {
        for (i=0; i<length; ++i) {
            data += (char) timedRead();
            if (!socket_client->connected()) {
                return false;
            }
        }
    }

    return true;
}

void WebSocketClient::disconnectStream() {
#ifdef DEBUGGING
    Serial.println(F("Terminating socket"));
#endif
    // Should send 0x8700 to server to tell it I'm quitting here.
    uint8_t quitCode[] = {0x87, 0x00};
    socket_client->write(quitCode, sizeof(quitCode));

    socket_client->flush();
    delay(10);
    socket_client->stop();
}

bool WebSocketClient::getData(String& data, uint8_t *opcode) {
    return handleStream(data, opcode);
}

void WebSocketClient::sendData(uint8_t *buf, uint16_t len, uint8_t opcode) {
#ifdef DEBUGGING
    Serial.print(F("Sending data: "));
    Serial.println(str);
#endif
    if (socket_client->connected()) {
        sendEncodedData((const uint8_t*)buf, len, opcode);
    }
}

void WebSocketClient::sendData(char *str, uint8_t opcode) {
    sendData((uint8_t*)str, strlen(str), opcode);
}

void WebSocketClient::sendData(String str, uint8_t opcode) {
    sendData(str.c_str(), opcode);
}

int WebSocketClient::timedRead() {
  while (!socket_client->available()) {
    delay(20);
  }

  return socket_client->read();
}

void WebSocketClient::sendEncodedData(const uint8_t *buf, uint16_t len, uint8_t opcode) {
    uint8_t *outBuf = new uint8_t[8+len];
    uint8_t outBufPos = 0;

    // Opcode; final fragment
    outBuf[outBufPos++] = (opcode | WS_FIN);

    // NOTE: no support for > 16-bit sized messages
    if (len > 125) {
        outBuf[outBufPos++] = (WS_SIZE16 | WS_MASK);
        outBuf[outBufPos++] = ((uint8_t) (len >> 8));
        outBuf[outBufPos++] = ((uint8_t) (len & 0xFF));
    } else {
        outBuf[outBufPos++] = ((uint8_t) len | WS_MASK);
    }

    uint8_t maskOffs = outBufPos;   // outBuf[outBufPos+i] represents mask[i], with i = 0...3
    for (uint8_t maskInd=0; maskInd<4; ++maskInd) {
        outBuf[outBufPos++] = random(0, 256);
    }
    //socket_client->write(outBuf, outBufPos);

    for (int i=0; i<len; ++i) {
        outBuf[outBufPos++] = buf[i] ^ outBuf[maskOffs + (i & 3)];
    }

    socket_client->write(outBuf, outBufPos);    // Send the whole output buffer all at once
    delete[] outBuf;    // Don't forget to free memory!
}
