const bip39 = require('bip39-light');
const cardanoWasm = require('@emurgo/cardano-serialization-lib-nodejs');

const cardanoNetwork = 'testnet';
console.log('NETWORK: ' + cardanoNetwork);
var mnemonic = bip39.generateMnemonic((32 * 15) / 3);
console.log('MNEMONIC: ' + mnemonic);

const entropy2 = bip39.mnemonicToEntropy(mnemonic);
const rootKey = cardanoWasm.Bip32PrivateKey.from_bip39_entropy(
  Buffer.from(entropy2, 'hex'),
  Buffer.from('')
);

const cip1852Account = rootKey
  .derive(1852 | 0x80000000) // hardened  Purpose.CIP1852
  .derive(1815 | 0x80000000) // hardened  CoinTypes.CARDANO
  .derive(0 | 0x80000000); // hardened account #0

const utxoPrivateKey = cip1852Account
  .derive(0) // 0=external 1=change (from BIP44)
  .derive(0); // addr index

const utxoPubKey = utxoPrivateKey.to_public();

const stakeKey = cip1852Account
  .derive(2) // from CIP1852
  .derive(0)
  .to_public();

const netid = cardanoNetwork === 'mainnet' ? cardanoWasm.NetworkInfo.mainnet().network_id() : cardanoWasm.NetworkInfo.testnet().network_id();

this.baseAddress = cardanoWasm.BaseAddress.new(
  netid,
  cardanoWasm.StakeCredential.from_keyhash(utxoPubKey.to_raw_key().hash()),
  cardanoWasm.StakeCredential.from_keyhash(stakeKey.to_raw_key().hash())
);

console.log('ADDRESS: ' + this.baseAddress.to_address().to_bech32());
