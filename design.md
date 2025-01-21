# Current design
## how ubores works
1. Client decided local port to expose, named X,  
2. Client sent request to server:CONTROL_PORT,  
3. Server assigned available port Y and sent response back to client:CONTROL_PORT  
4. Client received response from CONTROL_PORT and forward it to X

< LocalPort X > < --- plaintext --- > < Client > < --- CONTROL_PORT (ciphertext) --- > < Server > < --- Port Y (plaintext) --- > < Outer World >

## File organization
`main.rs`: The entry of the program  
`shared.rs`: Contains shared behaviors for both client and server.  
`server.rs`: Server side logic.  
`client.rs`: Client side logic.  
`auth.rs`: Provide encrypt/decrypt methods, currently supports `aes-128-gcm`, `chacha20poly-1305` and no encryption.

## Protocol
To safely handle UDP packet through Internet, the max datagram size of UDP is set to `512 Bytes`. The reliable transmit is
guaranteed by packet header and server side connection management. The header contains 6 field and is 8 bytes long, leaving `504 bytes` for actual data.  
**Note**: If encryption method was applied, the whole `512 Bytes` datagram will be encrypted, this includes `Header`, `Data`,
and `Paddings` (which fills the datagram if `Header` plus `Data` is less than 512 bytes).
### Header schema
Packet number: 1 byte  
Message type: 1 byte  
Authenticate type: 1 byte  
Fragment: 1 byte  
Connection ID: 2 bytes  
Data length: 2 Bytes  
### Handshake
Let's assume both client and server chose encrypt their traffic
1. Client sends `CLIENTHELLO` message with its `uuid` to Server in **plaintext**.
2. Server load corresponding `key` from configuration file with given `uuid`, and responds `SERVERHELLO` with `nonce` in **plaintext**.


