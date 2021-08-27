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



if you find something consider giving a finders fee to 

BTC:

36smNSqEBTRkCFvEvfNja53oSSx87toVEq

BCH:

qp5pweq9hvhxg23rjmsjra9etyvyzt9ycs3u4vs67v

ETH:

0xc1F4da3E06e0c122b23807A4465552337d1a0080
