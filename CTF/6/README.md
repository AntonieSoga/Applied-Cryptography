# 203 hours later...
It took you some time and effort, but you managed to identify the encryption scheme: AES-CBC. Looks like you hit another dead end, doesn't it?

Maybe you could find a way to break it if you had more ciphertexts, but that's not going to happen. You only have the one you found by doing a GET on "http://141.85.224.115:7204/encrypt" and that's it.
The first part is certainly the IV, but that does not help you decrypt anything if you do not have the key...

But wait! What's this?
You can POST an application/json with a 'ciphertext' to http://141.85.224.115:7204/oracle

I'll leave you get back at it then. 