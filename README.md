# Score Server Plugin

This plugin provides a WebSocket server that broadcasts high scores and live game scores in real-time for PinMAME games.
<img width="1220" height="1068" alt="image" src="https://github.com/user-attachments/assets/aea04641-4be3-43cd-9f6f-6918671abce6" />



## Features

- **WebSocket server on port 3131** - broadcasts scores to connected clients in real-time
- **Real-time current scores** - sends player scores, current player, and ball number as they change during gameplay
- **High scores broadcast** - sends structured high scores with player initials when games start/end
- **Change detection** - only broadcasts when game state actually changes (not time-based polling)
- **Automatic reconnection** - clients automatically reconnect if connection is lost
- **Structured JSON output** - high scores sent as JSON arrays, not text blobs
- Automatically detects the ROM being played
- Uses the [pinmame-nvram-maps](https://github.com/tomlogic/pinmame-nvram-maps) project to decode NVRAM data
- **Includes bundled NVRAM maps** - supports 628+ ROMs out of the box!

## Requirements

**None!** The plugin comes with all necessary NVRAM map files bundled. Just build and use!

## How It Works

### WebSocket Server

The plugin starts a WebSocket server on port **3131** that listens on all network interfaces (0.0.0.0). This allows:
- Local connections from `ws://localhost:3131`
- Network connections from `ws://<your-ip>:3131`
- Multiple clients can connect simultaneously

### Game Flow

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

### Message Types

The plugin sends two types of WebSocket messages:

#### High Scores
```json
{
  "type": "high_scores",
  "rom": "mm_109",
  "scores": [
    {"label": "Grand Champion", "initials": "WTH", "score": "3000000000"},
    {"label": "First Place", "initials": "ABC", "score": "1500000000"},
    {"label": "Second Place", "initials": "DEF", "score": "1000000000"}
  ]
}
```

#### Current Scores (Live Gameplay)
```json
{
  "type": "current_scores",
  "rom": "afm_113b",
  "players": 2,
  "current_player": 1,
  "current_ball": 2,
  "scores": [
    {"player": "Player 1", "score": "1234567890"},
    {"player": "Player 2", "score": "987654321"}
  ]
}
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

The plugin is built automatically when you build VPinball with CMake:

go into your `plugins` and clone repo:
```
git clone https://github.com/superhac/score-server.git
```

Edit `make/CMakeLists_plugins.txt` and add:
```
include("${CMAKE_SOURCE_DIR}/make/CMakeLists_plugin_ScoreServer.txt")
```

```
cmake --build . --target ScoreServerPlugin
```

The plugin will be installed to the `plugins/score-server/` directory.

## Configure your VPinballX.ini (enable the plugin)
```
[Plugin.ScoreServer]
Enable = 1
```

## Network Configuration

The WebSocket server listens on **port 3131** on all network interfaces.

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

  if (data.type === 'current_scores') {
    console.log(`${data.rom}: Player ${data.current_player} - Ball ${data.current_ball}`);
    data.scores.forEach(score => {
      console.log(`  ${score.player}: ${score.score}`);
    });
  }

  if (data.type === 'high_scores') {
    console.log(`High Scores for ${data.rom}:`);
    data.scores.forEach(entry => {
      console.log(`  ${entry.label}: ${entry.initials} - ${entry.score}`);
    });
  }
};
```

### Python
```python
import websocket
import json

def on_message(ws, message):
    data = json.loads(message)

    if data['type'] == 'current_scores':
        print(f"{data['rom']}: Player {data['current_player']} - Ball {data['current_ball']}")
        for score in data['scores']:
            print(f"  {score['player']}: {score['score']}")

    elif data['type'] == 'high_scores':
        print(f"High Scores for {data['rom']}:")
        for entry in data['scores']:
            print(f"  {entry['label']}: {entry['initials']} - {entry['score']}")

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
