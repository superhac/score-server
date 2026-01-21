# Score Server Plugin

This plugin broadcasts high scores and live game scores in real-time for both PinMAME games and ROM-less tables via WebSocket server or UDP endpoint.

<img width="1215" height="1063" alt="image" src="https://github.com/user-attachments/assets/ba2f07bf-4850-4fed-9032-f82dca1a634b" />

Prototype videos in action: [rom based](https://www.youtube.com/shorts/ERsjBmrbnQw), [non-rom + awards](https://www.youtube.com/shorts/ERsjBmrbnQw)
## Features

- **Flexible broadcasting** - supports WebSocket server, UDP endpoint, or both simultaneously
- **WebSocket server on port 3131** - broadcasts scores to connected clients in real-time
- **UDP endpoint support** - send JSON messages directly to a UDP receiver (low latency, fire-and-forget)
- **Machine ID tagging** - optionally tag all messages with a unique machine identifier
- **Game lifecycle tracking** - sends game_start and game_end messages with timestamps
- **Real-time current scores** - sends player scores, current player, and ball number as they change during gameplay
- **High scores broadcast** - sends structured high scores with player initials when games start/end
- **Badge/achievement system** - award and broadcast achievements in real-time
- **Timestamps on all messages** - ISO 8601 format (UTC) for precise event tracking
- **Change detection** - only broadcasts when game state actually changes (not time-based polling)
- **Automatic reconnection** - WebSocket clients automatically reconnect if connection is lost
- **Structured JSON output** - all messages sent as structured JSON
- **ROM-less table support** - scriptable API for tables without PinMAME ROMs
- **PinMAME integration** - automatically detects ROM being played and uses [pinmame-nvram-maps](https://github.com/tomlogic/pinmame-nvram-maps) to decode NVRAM data
- **Includes bundled NVRAM maps** - supports 628+ ROMs out of the box!

## Requirements

You must apply this [patch](https://github.com/vpinball/vpinball/commit/c1ca14346fc30c1ff883a28cf15ec0197a818a94) to the Pinmame plugin for this to work. 

## How It Works

### Broadcasting Modes

The plugin supports three broadcasting modes (configured via `BroadcastMode` in VPinballX.ini):

**WebSocket Mode (default):**
- Starts a WebSocket server on port **3131** listening on all network interfaces (0.0.0.0)
- Allows local connections from `ws://localhost:3131`
- Allows network connections from `ws://<your-ip>:3131`
- Multiple clients can connect simultaneously
- Includes message queuing and automatic reconnection support

**UDP Mode:**
- Sends JSON messages directly to a configured UDP endpoint
- Fire-and-forget delivery (no connection management)
- Very low latency
- Single endpoint only

**Both Mode:**
- Runs WebSocket server AND sends to UDP endpoint simultaneously
- Useful for local testing (WebSocket) plus remote aggregation (UDP)

### Game Flow

**For PinMAME Games:**

1. **On game start**:
   - Plugin captures the ROM name
   - Reads NVRAM from PinMAME Controller (live memory access)
   - Looks up ROM in pinmame-nvram-maps index
   - Loads corresponding JSON map file
   - Broadcasts high scores as structured JSON

2. **During gameplay**:
   - Monitors game state every frame
   - Detects changes in: player count, current player, current ball, and scores
   - Broadcasts updates only when state changes

3. **On game end**:
   - Broadcasts final high scores

**For ROM-less Tables:**

Tables can use the scriptable API to push score data directly:
- Call `SetGameName()` to identify the table
- Call `SetScoresArray()` to broadcast current scores
- Call `SetHighScoresArray()` to broadcast high scores
- Call `AwardBadge()` to send achievement events
- See [TABLE_INTEGRATION.md](TABLE_INTEGRATION.md) for complete documentation

### Message Types

The plugin sends six types of WebSocket messages. All messages include a `timestamp` field in ISO 8601 format (UTC). If `MachineId` is configured, all messages will also include a `machine_id` field identifying which machine the message originated from.

#### Table Loaded
Sent when a ROM-less table is loaded and initialized (ROM-less tables only).
```json
{
  "type": "table_loaded",
  "timestamp": "2026-01-15T12:30:00.123Z",
  "rom": "MyAwesomeTable",
  "machine_id": "Cabinet1"
}
```
*Note: This is sent when SetGameName() is called, typically in Table_Init. It indicates the table has loaded but the player hasn't started a game yet.*

#### Game Start
Sent when a new game begins (player starts playing).
```json
{
  "type": "game_start",
  "timestamp": "2026-01-15T12:34:56.789Z",
  "rom": "mm_109",
  "machine_id": "Cabinet1"
}
```
*Note: The `machine_id` field is only present if configured in VPinballX.ini*

#### Game End
Sent when a game ends.
```json
{
  "type": "game_end",
  "timestamp": "2026-01-15T12:45:30.123Z",
  "rom": "mm_109",
  "machine_id": "Cabinet1"
}
```

#### High Scores
Sent on game start and game end with the current high score table.
```json
{
  "type": "high_scores",
  "timestamp": "2026-01-15T12:34:56.890Z",
  "rom": "mm_109",
  "machine_id": "Cabinet1",
  "scores": [
    {"label": "Grand Champion", "initials": "WTH", "score": "3000000000"},
    {"label": "First Place", "initials": "ABC", "score": "1500000000"},
    {"label": "Second Place", "initials": "DEF", "score": "1000000000"}
  ]
}
```

#### Current Scores (Live Gameplay)
Sent whenever game state changes during active play.
```json
{
  "type": "current_scores",
  "timestamp": "2026-01-15T12:35:20.456Z",
  "rom": "afm_113b",
  "machine_id": "Cabinet1",
  "players": 2,
  "current_player": 1,
  "current_ball": 2,
  "scores": [
    {"player": "Player 1", "score": "1234567890"},
    {"player": "Player 2", "score": "987654321"}
  ]
}
```

#### Badge/Achievement
Sent when a badge or achievement is awarded (ROM-less tables only).
```json
{
  "type": "badge",
  "timestamp": "2026-01-15T12:40:15.789Z",
  "rom": "MyAwesomeTable",
  "machine_id": "Cabinet1",
  "player": "Player 1",
  "name": "Millionaire",
  "description": "Scored over 1,000,000 points"
}
```

## ROM-less Table Integration

For tables that don't use PinMAME ROMs, you can use the scriptable API to broadcast scores. See [TABLE_INTEGRATION.md](TABLE_INTEGRATION.md) for a complete guide with examples.

Quick example:
```vbscript
Const GAME_STATE_START = 1
Const GAME_STATE_PLAYING = 2
Const GAME_STATE_END = 3

Sub Table_Init()
    Dim Server
    Set Server = CreateObject("VPinball.ScoreServer")
    Server.SetGameName "MyTable_v1.0"
    Server.SetGameState 1, 1, 1, GAME_STATE_START  ' playerCount, currentPlayer, currentBall, gameState
End Sub

Sub AddScore(points)
    Score(CurrentPlayer) = Score(CurrentPlayer) + points

    Dim Server
    Set Server = CreateObject("VPinball.ScoreServer")
    Server.SetScoresArray Join(playerNames, "|"), Join(scores, "|")
    Server.SetGameState PlayersPlayingGame, CurrentPlayer, CurrentBall, GAME_STATE_PLAYING
End Sub
```

## Test Client

A test WebSocket client is included: `test-websocket.html`

Features:
- Automatically connects on page load
- Retries connection every 1 second if disconnected
- Displays parsed messages in a readable format
- Shows raw JSON for debugging
- Color-coded message types

To use:
1. Open `test-websocket.html` in a web browser
2. Update the IP address if connecting from another machine
3. The page will automatically connect and show live scores

## Supported Encodings

The plugin supports multiple NVRAM encoding formats:

- **BCD (Binary-Coded Decimal)**: Used for scores on most machines
- **CH (Character)**: Used for player initials
- **INT**: Used for integer values on some machines

## Supported Games

The plugin supports any game that has a map file in the pinmame-nvram-maps repository (628+ ROMs). This includes:

- Williams WPC games (Medieval Madness, Attack from Mars, Monster Bash, etc.)
- Williams System 11 games
- Stern Whitestar games
- Stern SAM/SPIKE games
- Data East games
- Gottlieb System 80/80A/80B games
- Bally games
- And many more!

Check the [pinmame-nvram-maps repository](https://github.com/tomlogic/pinmame-nvram-maps) for a complete list of supported games.

## Building
Copy CMakeLists_plugin_ScoreServer.txt (when your inside the score-server dir)

```
cp CMakeLists_plugin_ScoreServer.txt ../../make/
```

The plugin is built automatically when you build VPinball with CMake:

```bash
cmake --build . --target ScoreServerPlugin
```

The plugin will be installed to the `plugins/score-server/` directory.

## Configuration

Configure the plugin in your `VPinballX.ini` file:

```ini
[Plugin.ScoreServer]
Enable = 1
MachineId = MyPinballCabinet
; 1=WebSocket or 2=UDP or 3=Both
BroadcastMode = 1
UdpHost = 192.168.1.100
UdpPort = 9000
```

### Configuration Options

- **Enable** (required): Set to `1` to enable the plugin
- **MachineId** (optional): A unique identifier for this machine. When set, all WebSocket messages will include a `machine_id` field to identify which cabinet the message originated from. This is useful when broadcasting scores from multiple machines to the same client.
- **BroadcastMode** (optional): Select how to broadcast messages. Options:
  - `WebSocket` (default): Run WebSocket server on port 3131 for clients to connect
  - `UDP`: Send messages to a UDP endpoint (no WebSocket server)
  - `Both`: Run WebSocket server AND send to UDP endpoint
- **UdpHost** (required if BroadcastMode is UDP or Both): Hostname or IP address of the UDP endpoint (e.g., `192.168.1.100` or `myserver.com`)
- **UdpPort** (required if BroadcastMode is UDP or Both): Port number of the UDP endpoint (e.g., `9000`)

## Network Configuration

### WebSocket Mode

The WebSocket server listens on **port 3131** on all network interfaces. This is the default mode.

**Pros:**
- Multiple clients can connect simultaneously
- Clients automatically receive all messages in real-time
- Includes automatic reconnection logic
- Message queue for first 60 seconds ensures no data loss during startup

**Cons:**
- Requires clients to maintain persistent connections
- More complex client implementation

### UDP Mode

In UDP mode, the plugin sends JSON messages directly to a configured endpoint via UDP packets.

**Pros:**
- Fire-and-forget messaging (no connection management)
- Very low latency
- Simple receiver implementation (just listen on a UDP port)
- No WebSocket overhead

**Cons:**
- No delivery guarantee (messages may be lost in network congestion)
- No message queuing
- Single endpoint only

**Example UDP receiver (Python):**
```python
import socket
import json

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', 9000))

print("Listening for UDP messages on port 9000...")
while True:
    data, addr = sock.recvfrom(65535)
    message = json.loads(data.decode('utf-8'))
    print(f"Received from {addr}: {message['type']}")
```

**Example UDP receiver (Node.js):**
```javascript
const dgram = require('dgram');
const server = dgram.createSocket('udp4');

server.on('message', (msg, rinfo) => {
  const data = JSON.parse(msg.toString());
  console.log(`Received ${data.type} from ${rinfo.address}:${rinfo.port}`);
});

server.bind(9000);
console.log('Listening for UDP messages on port 9000...');
```

### Both Mode

When set to `Both`, the plugin runs both the WebSocket server and sends to the UDP endpoint simultaneously. This is useful when you want:
- Local WebSocket clients for testing/debugging
- Remote UDP endpoint for production score aggregation

### Firewall Configuration

If connecting from external machines, ensure port 3131 is open:

**Linux (iptables):**
```bash
sudo iptables -A INPUT -p tcp --dport 3131 -j ACCEPT
```

**Linux (firewalld):**
```bash
sudo firewall-cmd --permanent --add-port=3131/tcp
sudo firewall-cmd --reload
```

**Windows:**
```powershell
New-NetFirewallRule -DisplayName "VPinball Score Server" -Direction Inbound -LocalPort 3131 -Protocol TCP -Action Allow
```

## Integration Examples

### JavaScript/Node.js
```javascript
const ws = new WebSocket('ws://192.168.1.100:3131');

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);

  // Optional: Check which machine sent this message
  const machine = data.machine_id ? `[${data.machine_id}] ` : '';

  if (data.type === 'table_loaded') {
    console.log(`${machine}[${data.timestamp}] Table loaded: ${data.rom}`);
  }

  if (data.type === 'game_start') {
    console.log(`${machine}[${data.timestamp}] Game started: ${data.rom}`);
  }

  if (data.type === 'game_end') {
    console.log(`${machine}[${data.timestamp}] Game ended: ${data.rom}`);
  }

  if (data.type === 'current_scores') {
    console.log(`${machine}[${data.timestamp}] ${data.rom}: Player ${data.current_player} - Ball ${data.current_ball}`);
    data.scores.forEach(score => {
      console.log(`  ${score.player}: ${score.score}`);
    });
  }

  if (data.type === 'high_scores') {
    console.log(`${machine}[${data.timestamp}] High Scores for ${data.rom}:`);
    data.scores.forEach(entry => {
      console.log(`  ${entry.label}: ${entry.initials} - ${entry.score}`);
    });
  }

  if (data.type === 'badge') {
    console.log(`${machine}[${data.timestamp}] 🏆 ${data.player} - Achievement unlocked: ${data.name}`);
    console.log(`  ${data.description}`);
  }
};
```

### Python
```python
import websocket
import json

def on_message(ws, message):
    data = json.loads(message)

    # Optional: Check which machine sent this message
    machine = f"[{data['machine_id']}] " if 'machine_id' in data else ''

    if data['type'] == 'table_loaded':
        print(f"{machine}[{data['timestamp']}] Table loaded: {data['rom']}")

    elif data['type'] == 'game_start':
        print(f"{machine}[{data['timestamp']}] Game started: {data['rom']}")

    elif data['type'] == 'game_end':
        print(f"{machine}[{data['timestamp']}] Game ended: {data['rom']}")

    elif data['type'] == 'current_scores':
        print(f"{machine}[{data['timestamp']}] {data['rom']}: Player {data['current_player']} - Ball {data['current_ball']}")
        for score in data['scores']:
            print(f"  {score['player']}: {score['score']}")

    elif data['type'] == 'high_scores':
        print(f"{machine}[{data['timestamp']}] High Scores for {data['rom']}:")
        for entry in data['scores']:
            print(f"  {entry['label']}: {entry['initials']} - {entry['score']}")

    elif data['type'] == 'badge':
        print(f"{machine}[{data['timestamp']}] 🏆 {data['player']} - Achievement unlocked: {data['name']}")
        print(f"  {data['description']}")

ws = websocket.WebSocketApp('ws://192.168.1.100:3131',
                           on_message=on_message)
ws.run_forever()
```

## Troubleshooting

### WebSocket won't connect

1. Check VPinball log for "WebSocket server listening on 0.0.0.0:3131"
2. Verify firewall allows port 3131
3. Test local connection first: `ws://localhost:3131`
4. For network connections, use the machine's IP: `ws://192.168.1.xxx:3131`

### No high scores received

1. Check the VPinball log for error messages
2. Ensure the ROM has a map file in pinmame-nvram-maps
3. Verify PinMAME is running and game has started
4. Check WebSocket client is properly parsing JSON

### "No map found for ROM" error

The ROM you're playing doesn't have a map file yet. You can:
1. Check if there's a similar ROM that uses the same map
2. Create a map file following the [mapping guide](https://github.com/tomlogic/pinmame-nvram-maps)
3. Contribute the map back to the project!

## Performance

- **Low overhead**: Change detection ensures minimal CPU usage
- **Efficient broadcasting**: Only sends data when state changes
- **Multi-client**: Supports multiple WebSocket clients simultaneously
- **No polling**: Uses event-driven architecture (onPrepareFrame hook)

## Credits

- Uses the [pinmame-nvram-maps](https://github.com/tomlogic/pinmame-nvram-maps) project by Tom Collins
- Built on the VPinball plugin architecture
- WebSocket protocol implementation with SHA-1 handshake and Base64 encoding
