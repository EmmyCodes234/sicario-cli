import * as path from "path";
import {
  ExtensionContext,
  commands,
  window,
  workspace,
} from "vscode";
import {
  LanguageClient,
  LanguageClientOptions,
  ServerOptions,
  TransportKind,
} from "vscode-languageclient/node";

let client: LanguageClient | undefined;

export function activate(context: ExtensionContext): void {
  const config = workspace.getConfiguration("sicario");
  const sicarioPath: string = config.get("path", "sicario");

  const serverOptions: ServerOptions = {
    command: sicarioPath,
    args: ["lsp"],
    transport: TransportKind.stdio,
  };

  const clientOptions: LanguageClientOptions = {
    documentSelector: [
      { scheme: "file", language: "javascript" },
      { scheme: "file", language: "javascriptreact" },
      { scheme: "file", language: "typescript" },
      { scheme: "file", language: "typescriptreact" },
      { scheme: "file", language: "python" },
      { scheme: "file", language: "rust" },
      { scheme: "file", language: "go" },
      { scheme: "file", language: "java" },
    ],
    diagnosticCollectionName: "sicario",
    outputChannelName: "Sicario",
  };

  client = new LanguageClient(
    "sicario",
    "Sicario Security Scanner",
    serverOptions,
    clientOptions
  );

  // Register the "Scan Workspace" command.
  const scanCmd = commands.registerCommand("sicario.scanWorkspace", async () => {
    if (!client) {
      window.showErrorMessage("Sicario LSP client is not running.");
      return;
    }
    window.showInformationMessage("Sicario: Scanning workspace...");
    // Re-open all visible editors to trigger didOpen → scan.
    for (const editor of window.visibleTextEditors) {
      const doc = editor.document;
      if (doc.uri.scheme === "file") {
        // Sending a didSave notification triggers a full scan.
        await client.sendNotification("textDocument/didSave", {
          textDocument: { uri: doc.uri.toString() },
        });
      }
    }
    window.showInformationMessage("Sicario: Workspace scan complete.");
  });

  context.subscriptions.push(scanCmd);

  // Start the client (and server).
  client.start();
}

export function deactivate(): Thenable<void> | undefined {
  if (!client) {
    return undefined;
  }
  return client.stop();
}
