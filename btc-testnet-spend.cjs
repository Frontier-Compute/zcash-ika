/**
 * BTC testnet spend via Ika dWallet.
 * 
 * Same secp256k1 dWallet that signed Zcash mainnet TX Hcn1cW27nELwPog7xwfedNE1kGAsSzSmFy5whGALw77b
 * now signs a Bitcoin testnet transaction. Universal UTXO custody.
 *
 * Usage: node btc-testnet-spend.js [recipient_address] [amount_sats]
 * Defaults: send 1000 sats to tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx (Bitcoin wiki testnet addr)
 */

const {
  deriveBitcoinAddress,
  fetchBtcUTXOs,
  selectBtcUTXOs,
  buildUnsignedBtcTx,
  attachBtcSignatures,
  broadcastBtcTx,
  sign,
} = require('./dist/index.js');

const DWALLET_ID = '0x108c8e98d0384d3eef7e65e6abd4613fdc23ca3fca2fe1badd60d54ab8e84c90';
const ENC_SEED = '3d2405772cb3d5439a49fd59c576294dacf8da24fb4f925af6db8888e9b3e433';
const PUBKEY_HEX = '03d691c837d008538ffbbb60438dad338b9b6a1a732b1b17096f890c9abdc12cb7';
const SUI_PRIV = 'suiprivkey1qq4t7um66lkvta4n8fqcc8cl3mwmz7mrtgcwlgavfascv7ent8pt2s50amc';

async function main() {
  // Default: send back to ourselves (proves signing works without losing funds)
  const recipient = process.argv[2] || ourAddress;
  const amount = parseInt(process.argv[3] || '1000', 10);

  const pubkey = Buffer.from(PUBKEY_HEX, 'hex');
  const ourAddress = deriveBitcoinAddress(pubkey, 'testnet');
  console.log('Our BTC testnet address:', ourAddress);
  console.log('Recipient:', recipient);
  console.log('Amount:', amount, 'sats');

  // Step 1: Fetch UTXOs
  console.log('\n[1/6] Fetching UTXOs...');
  const utxos = await fetchBtcUTXOs(ourAddress, 'testnet');
  console.log('Found', utxos.length, 'UTXOs');
  if (utxos.length === 0) {
    console.error('No UTXOs. Fund this address first:', ourAddress);
    process.exit(1);
  }
  const totalBalance = utxos.reduce((s, u) => s + u.value, 0);
  console.log('Total balance:', totalBalance, 'sats');

  // Step 2: Select UTXOs + build unsigned TX
  console.log('\n[2/6] Building unsigned transaction...');
  const feeRate = 5; // sat/vbyte
  const { selected, fee } = selectBtcUTXOs(utxos, amount, feeRate);
  console.log('Selected', selected.length, 'UTXOs, fee:', fee, 'sats');

  const { sighashes, inputs, outputs } = buildUnsignedBtcTx(
    selected,
    [{ address: recipient, value: amount }],
    ourAddress,
    fee
  );
  console.log('Computed', sighashes.length, 'sighash(es)');

  // Step 3: Sign each sighash via Ika MPC
  const config = {
    network: 'testnet',
    suiPrivateKey: SUI_PRIV,
  };

  const signatures = [];
  for (let i = 0; i < sighashes.length; i++) {
    console.log(`\n[3/6] Signing input ${i + 1}/${sighashes.length} via Ika dWallet...`);
    console.log('Sighash:', sighashes[i].toString('hex'));
    const result = await sign(config, {
      messageHash: new Uint8Array(sighashes[i]),
      walletId: DWALLET_ID,
      chain: 'bitcoin',
      encryptionSeed: ENC_SEED,
    });
    console.log('Signature obtained, Sui TX:', result.signTxDigest);
    signatures.push(Buffer.from(result.signature));
  }

  // Step 4: Attach signatures
  console.log('\n[4/6] Attaching signatures...');
  const signedTx = attachBtcSignatures(inputs, outputs, signatures, pubkey);
  const txHex = signedTx.toString('hex');
  console.log('Signed TX hex:', txHex.substring(0, 80), '...');
  console.log('TX size:', txHex.length / 2, 'bytes');

  // Step 5: Broadcast
  console.log('\n[5/6] Broadcasting...');
  const txid = await broadcastBtcTx(txHex, 'testnet');
  console.log('BROADCAST SUCCESS');
  console.log('TXID:', txid);
  console.log('Explorer: https://blockstream.info/testnet/tx/' + txid);

  // Step 6: Summary
  console.log('\n[6/6] Universal UTXO custody proven.');
  console.log('Same dWallet', DWALLET_ID.substring(0, 16) + '...');
  console.log('  Zcash mainnet: t1JgBmDT2Q4Bgj3obsZ5BYsH86Yd2GP8NBf (already signed)');
  console.log('  Bitcoin testnet:', ourAddress, '(just signed)');
}

main().catch(e => {
  console.error('FAILED:', e.message || e);
  process.exit(1);
});
