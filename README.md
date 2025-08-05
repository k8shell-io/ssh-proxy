# ssh-proxy

When forking is enabled, the server spawns a subprocess to handle each connection.
The below diagram illustrates the flow:

```
SSH Client → Server.acceptConnections() → handleConnectionWithProcess() → 
  └── Spawns subprocess: ./ssh-proxy --handle-connection-fd 3 --config config.yaml
      └── main.go detects --handle-connection-fd flag
          └── Calls HandleConnectionFromFD(3, configPath)
              └── Creates connection from FD 3
                  └── Calls handleConnection() in subprocess
