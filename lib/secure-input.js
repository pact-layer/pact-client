import { createInterface } from "node:readline";

async function readAll(input) {
  const chunks = [];
  for await (const chunk of input) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  return Buffer.concat(chunks).toString("utf8").trim();
}

/** Read a secret from stdin without echoing when stdin is an interactive TTY. */
export async function readSecretInput({ input = process.stdin, output = process.stderr, prompt = "Secret: " } = {}) {
  if (!input.isTTY) return readAll(input);

  output.write(prompt);
  const readline = createInterface({ input, output, terminal: true });
  // readline owns terminal echo while raw mode is active. Suppress every redraw
  // so the secret never appears in terminal output, including during edits.
  readline._writeToOutput = () => {};

  try {
    return (
      await new Promise((resolve, reject) => {
        const onError = (error) => reject(error);
        input.once("error", onError);
        readline.once("SIGINT", () => reject(new Error("input cancelled")));
        readline.question("", (answer) => {
          input.off("error", onError);
          resolve(answer);
        });
      })
    ).trim();
  } finally {
    readline.close();
    output.write("\n");
  }
}
