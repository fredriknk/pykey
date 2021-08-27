pywallet/keyhunter combination for finding bitcoin wallets in a binary hexdump and making wallet addresses, 
if it finds an unencrypted private key, it will convert it to an address and check how much btc has been 
transferred to it to see if it is an actual real address with activity, it allso saves the resulting hex 
positions in ascii json with the same name as the image with .result appended.

There are two testfiles to see how the script works, testfile.test (just a binary file with magic bits embedded) 
and testfile2(wallet).test, a dummy encrypted wallet file i found online.

usage:

$python3 pykey.py ./filename.img

output
./filename.img.result

containing:
{'berkley': ['0xc', '0x200c'], 'bitcoin_word': [], 'bitcoin_old_wal_key': [], 'bitcoin_keymeta': [], 'bitcoin_defaultkey': ['0xbe69'], 'bitcoin_minversion': ['0xbe31'], 'bitcoin_bestblock': [], 'bitcoin_acc': ['0x4fed'], 'bitcoin_ke
y': [], 'bitcoin_ckey_Encrypted_key': ['0x30f5', '0x5855', '0x58b5', '0x5915', '0x8fd5', '0x9d35', '0x9d95', '0x9df5', '0x9e55', '0x9eb5', '0x9f15', '0x9f75', '0x9fd5', '0xbd2d', '0xbd8d'], 'b
itcoin_mkey_encrypted_wallets': ['0x9cf5', '0xbced'], 'bitcoin_name': ['0x9c15', '0x9c51', '0x9c81', '0xbc0d', '0xbc49', '0xbc79'], 'bitcoin_purpose': [], 'bitcoin_bitcoin_qt_blockchain': [], 'bitcoin_multibit_wallet_file': [], 'bit
coin_multibit_bitcoin_info': [], 'ethereum_ciphrtext': [], 'ethereum_word': []}





#if you find something consider giving a finders fee to 

BTC:

36smNSqEBTRkCFvEvfNja53oSSx87toVEq

BCH:

qp5pweq9hvhxg23rjmsjra9etyvyzt9ycs3u4vs67v

ETH:

0xc1F4da3E06e0c122b23807A4465552337d1a0080
