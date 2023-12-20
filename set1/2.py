hex1 = "1c0111001f010100061a024b53535009181c"
bstr1 = bytes.fromhex(hex1)

hex2 = "686974207468652062756c6c277320657965"
bstr2 = bytes.fromhex(hex2)

xored = [ a ^ b for (a,b) in zip(bstr1, bstr2) ]
print(bytes(xored).hex())
