import { generateMnemonic, mnemonicToSeedSync, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english";

export const newMnemonic = (strength: 128 | 256 = 128) => generateMnemonic(wordlist, strength);
export const isMnemonic = (m: string) => validateMnemonic(m, wordlist);
/** BIP39 master seed, 64 bytes. */
export const mnemonicToSeed = (m: string, passphrase = "") => mnemonicToSeedSync(m, passphrase);
