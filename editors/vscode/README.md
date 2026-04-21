# Sicario for VS Code

Real-time SAST security scanning powered by the Sicario engine.

## Features

- Live security diagnostics as you type (debounced 500ms)
- Severity-appropriate squiggles: Critical/High → red, Medium → yellow, Low/Info → blue
- Quick-fix code actions to suppress findings with inline comments
- "Sicario: Scan Workspace" command for full workspace scanning

## Requirements

The `sicario` binary must be installed and available on your `PATH`, or configured
via the `sicario.path` setting.

## Settings

| Setting                      | Default    | Description                        |
|------------------------------|------------|------------------------------------|
| `sicario.path`               | `sicario`  | Path to the sicario binary         |
| `sicario.severityThreshold`  | `low`      | Minimum severity level to display  |

## Building

```bash
cd editors/vscode
npm install
npm run compile
npm run package   # produces .vsix file
```
