# ScoreServer Table Integration Guide

This guide explains how to integrate the ScoreServer plugin into ROM-less Visual Pinball tables to broadcast scores, high scores, and achievements via WebSocket.

## Overview

The ScoreServer plugin exposes a `ScoreServerClass` object that table scripts can call to push score data in real-time. This is designed for tables that don't use PinMAME ROMs and store scores in VBScript variables.

## Setup in Table Script

### Optional Plugin Availability

The ScoreServer plugin is optional. To make your table work with or without it, create the object once globally and check before using:

```vbscript
' Global variable - created once at table init
Dim ScoreServer

Sub Table_Init()
    ' Try to create the plugin object once
    On Error Resume Next
    Set ScoreServer = CreateObject("VPinball.ScoreServer")
    On Error Goto 0

    ' If plugin is available, initialize it
    If Not ScoreServer Is Nothing Then
        ScoreServer.SetGameName "MyTable"
    End If
End Sub

' Throughout your code, just check if the object exists
Sub AddScore(points)
    Score(CurrentPlayer) = Score(CurrentPlayer) + points

    If Not ScoreServer Is Nothing Then
        ScoreServer.SetScoresArray Join(playerNames, "|"), Join(scoreStrings, "|")
    End If
End Sub
```

**Benefits:**
- Create object once, not on every call
- Simple `If Not ScoreServer Is Nothing` check everywhere
- No crashes whether plugin is enabled or disabled

### 1. Initialize the Plugin (in Table_Init)

```vbscript
' Global variable
Dim ScoreServer

Sub Table_Init()
    ' Create plugin object once
    On Error Resume Next
    Set ScoreServer = CreateObject("VPinball.ScoreServer")
    On Error Goto 0

    ' Initialize if available
    If Not ScoreServer Is Nothing Then
        ScoreServer.SetGameName "MyAwesomeTable"
    End If

    ' Your other initialization code...
End Sub
```

### 2. Update Scores During Gameplay

```vbscript
' Player scores array
Dim Score(4)  ' Supports up to 4 players

Sub AddScore(points)
    Score(CurrentPlayer) = Score(CurrentPlayer) + points

    ' Broadcast scores if plugin is available
    If Not ScoreServer Is Nothing Then
        Dim playerNames(4), scoreStrings(4), i
        For i = 1 To PlayersPlayingGame
            playerNames(i-1) = "Player " & i
            scoreStrings(i-1) = CStr(Score(i))
        Next
        ScoreServer.SetScoresArray Join(playerNames, "|"), Join(scoreStrings, "|")
    End If
End Sub
```

### 3. Update Game State

```vbscript
Sub UpdateGameState()
    If Not ScoreServer Is Nothing Then
        ScoreServer.SetGameState PlayersPlayingGame, CurrentPlayer, BallsPerGame
    End If
End Sub
```

### 4. Set High Scores

```vbscript
Sub SaveHighScoresArray()
    If Not ScoreServer Is Nothing Then
        ' If you have arrays of high scores, use Join() to combine them
        ' SetHighScoresArray uses pipe "|" as delimiter
        ScoreServer.SetHighScoresArray _
            Join(HighScoreLabel, "|"), _
            Join(HighScoreName, "|"), _
            Join(HighScore, "|")
    End If
End Sub
```

### 5. Award Badges/Achievements

```vbscript
Sub CheckAchievements()
    If Not ScoreServer Is Nothing Then
        ' Award a badge when player reaches milestone
        If Score(CurrentPlayer) >= 1000000 Then
            ScoreServer.AwardBadge "Player " & CurrentPlayer, "Millionaire", "Scored over 1,000,000 points"
        End If

        ' Award for completing modes
        If AllModesCompleted Then
            ScoreServer.AwardBadge "Player " & CurrentPlayer, "Mode Master", "Completed all table modes"
        End If
    End If
End Sub
```

### 6. Clean Up (on Game End)

```vbscript
Sub EndOfGame()
    If Not ScoreServer Is Nothing Then
        ScoreServer.ClearState
    End If

    ' Your other cleanup code...
End Sub
```

## Complete Example

```vbscript
'*************************************
' Table Variables
'*************************************
Dim ScoreServer  ' Global plugin object
Dim Score(4)
Dim PlayersPlayingGame
Dim CurrentPlayer
Dim CurrentBall
Dim BallsPerGame

'*************************************
' Table Initialization
'*************************************
Sub Table_Init()
    ' Create plugin object once
    On Error Resume Next
    Set ScoreServer = CreateObject("VPinball.ScoreServer")
    On Error Goto 0

    ' Initialize if available
    If Not ScoreServer Is Nothing Then
        ScoreServer.SetGameName "AwesomeTable_v1.0"
    End If

    PlayersPlayingGame = 1
    CurrentPlayer = 1
    CurrentBall = 1
    BallsPerGame = 3

    For i = 1 To 4
        Score(i) = 0
    Next

    UpdateGameState
End Sub

'*************************************
' Scoring
'*************************************
Sub AddScore(points)
    Score(CurrentPlayer) = Score(CurrentPlayer) + points

    ' Update WebSocket clients with all scores
    If Not ScoreServer Is Nothing Then
        Dim playerNames(4), scoreStrings(4), i
        For i = 1 To PlayersPlayingGame
            playerNames(i-1) = "Player " & i
            scoreStrings(i-1) = CStr(Score(i))
        Next
        ScoreServer.SetScoresArray Join(playerNames, "|"), Join(scoreStrings, "|")
    End If

    ' Check for achievements
    CheckAchievements
End Sub

'*************************************
' Game State Updates
'*************************************
Sub UpdateGameState()
    If Not ScoreServer Is Nothing Then
        ScoreServer.SetGameState PlayersPlayingGame, CurrentPlayer, CurrentBall
    End If
End Sub

Sub NextBall()
    CurrentBall = CurrentBall + 1
    If CurrentBall > BallsPerGame Then
        CurrentBall = 1
        CurrentPlayer = CurrentPlayer + 1
        If CurrentPlayer > PlayersPlayingGame Then
            EndOfGame
            Exit Sub
        End If
    End If
    UpdateGameState
End Sub

'*************************************
' Achievements
'*************************************
Sub CheckAchievements()
    If Not ScoreServer Is Nothing Then
        If Score(CurrentPlayer) >= 100000 Then
            ScoreServer.AwardBadge "Player " & CurrentPlayer, "Bronze Medal", "Scored 100,000 points"
        End If

        If Score(CurrentPlayer) >= 500000 Then
            ScoreServer.AwardBadge "Player " & CurrentPlayer, "Silver Medal", "Scored 500,000 points"
        End If

        If Score(CurrentPlayer) >= 1000000 Then
            ScoreServer.AwardBadge "Player " & CurrentPlayer, "Gold Medal", "Scored 1,000,000 points"
        End If
    End If
End Sub

'*************************************
' Game End
'*************************************
Sub EndOfGame()
    ' Find winner and check if it's a high score
    Dim highestScore, winner
    highestScore = 0
    winner = 1

    For i = 1 To PlayersPlayingGame
        If Score(i) > highestScore Then
            highestScore = Score(i)
            winner = i
        End If
    Next

    ' Update high scores (in a real table, you'd check against saved high scores)
    ' Example: broadcast last game winner
    If Not ScoreServer Is Nothing Then
        If highestScore > 0 Then
            ScoreServer.SetHighScoresArray "Last Game Winner", "P" & winner, CStr(highestScore)
        End If

        ' Clear state
        ScoreServer.ClearState
    End If
End Sub
```

## WebSocket Message Formats

### Current Scores
```json
{
  "type": "current_scores",
  "timestamp": "2026-01-15T12:35:20.456Z",
  "rom": "AwesomeTable_v1.0",
  "players": 2,
  "current_player": 1,
  "current_ball": 2,
  "scores": [
    {"player": "Player 1", "score": "1234567"},
    {"player": "Player 2", "score": "987654"}
  ]
}
```

### High Scores
```json
{
  "type": "high_scores",
  "timestamp": "2026-01-15T12:45:30.123Z",
  "rom": "AwesomeTable_v1.0",
  "scores": [
    {"label": "Grand Champion", "initials": "ABC", "score": "5000000"},
    {"label": "First Place", "initials": "DEF", "score": "3000000"}
  ]
}
```

### Badge/Achievement
Each badge is sent as an individual event when awarded:
```json
{
  "type": "badge",
  "timestamp": "2026-01-15T12:40:15.789Z",
  "rom": "AwesomeTable_v1.0",
  "player": "Player 1",
  "name": "Bronze Medal",
  "description": "Scored 100,000 points"
}
```

## Available Methods

| Method | Parameters | Description |
|--------|------------|-------------|
| `SetGameName` | `string gameName` | Set the game name (must be called first) |
| `SetGameState` | `int playerCount, int currentPlayer, int currentBall` | Update game state |
| `SetScoresArray` | `string playersDelimited, string scoresDelimited` | Set all player names and scores using pipe-delimited strings |
| `SetHighScoresArray` | `string labelsDelimited, string initialsDelimited, string scoresDelimited` | Set all high scores at once using pipe-delimited strings |
| `AwardBadge` | `string player, string name, string description` | Award an achievement to a specific player (sends badge event immediately) |
| `ClearState` | none | Clear all state (call on game end) |

## Testing

1. Enable the ScoreServer plugin in `VPinballX.ini`:
   ```ini
   [Plugin.ScoreServer]
   Enable = 1
   ```

2. Load your table

3. Open `plugins/score-server/test-websocket.html` in a browser

4. Play the table and watch the scores update in real-time!

## Tips

- **Optional plugin support**: Create the ScoreServer object once globally in `Table_Init()`, then just use `If Not ScoreServer Is Nothing` checks everywhere - simple and efficient!
- Call `SetGameName` early in `Table_Init` to identify your table
- Use `SetScoresArray` with `Join()` to broadcast all player scores efficiently
- Use `SetHighScoresArray` with `Join()` to broadcast all high scores in a single message
- Each `AwardBadge()` call sends a badge event immediately - the table script should handle deduplication if needed
- Always call `ClearState` at the end of the game to reset for the next game
- The "rom" field in WebSocket messages will contain your game name
- The pipe delimiter `"|"` is used by `Join()` to combine array elements
