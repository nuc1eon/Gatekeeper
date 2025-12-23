// Description: Enter your pin to securely store it as Argon2 hash in a file "pin.hash".
// Usage: node set-pin.js

const fs = require('fs');
const path = require('path');
const argon2 = require('argon2');

// small function to hide user input and replace it with asterisks
function hidden(prompt) {
  return new Promise((resolve) => {
    const readline = require('readline');
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    // small wrapper that prevents echoing by temporarily overriding write
    const origWrite = rl._writeToOutput;
    rl._writeToOutput = function(stringToWrite) {
      // show the prompt but mask any user input characters
      if (rl.stdoutMuted) {
        if (stringToWrite.startsWith(prompt)) {
          origWrite.call(rl, prompt);
        } else {
          origWrite.call(rl, '*');
        }
      } else {
        origWrite.call(rl, stringToWrite);
      }
    };

    rl.stdoutMuted = true;
    // print prompt immediately and ask
    rl.question(prompt, (answer) => {
      rl.close();
      resolve(answer);
    });
    // after closing, restore behavior
    rl.on('close', () => { rl._writeToOutput = origWrite; rl.stdoutMuted = false; process.stdout.write('\n'); });
  });
}

(async () => {
  try {
    const pin1 = await hidden('Enter new PIN: ');
    if (!pin1) { console.error('PIN cannot be empty'); process.exit(1); }
    const pin2 = await hidden('Confirm PIN: ');
    if (pin1 !== pin2) { console.error('PINs do not match'); process.exit(1); }

    const hash = await argon2.hash(pin1, {
      type: argon2.argon2id,
      timeCost: 2,
      memoryCost: 64 * 1024,
      parallelism: 1
    });

    const outPath = path.join(__dirname, 'pin.hash');
    fs.writeFileSync(outPath, hash + '\n', { mode: 0o600 });
    fs.chmodSync(outPath, 0o600);
    console.log('PIN hash saved to pin.hash (permissions 600). Do not commit this file.');
    process.exit(0);
  } catch (err) {
    console.error('Error:', err.message || err);
    process.exit(1);
  }
})();
