See [Theory](https://za3k.com/ok-mixnet.md) over on my site for the explanation of how the mixnet works.

To use it, you will need:
- A computer which is on and connected to the internet 24/7. 
- Linux. If you're not running Linux you can probably modify the python code without too much work. Only the random-number source is Linux-specific.
- A good source of random numbers, such as a hardware random number generator. **This is an alpha proof of concept that uses /dev/urandom by default, which is not a good source.** To change the source of random numbers, modify the source code from '/dev/urandom' to whatever source device you wish.
- Your computer needs to have a publicly available IP address (you may need to set up port forwarding for TCP port 17928). OK-Mixnet is IPv4 only, sorry.
- To be on the list! Email me (my email is [here](za3k.com)) to join the network. 
- A friend you want to talk to who is also on the mixnet.

To send a message to a friend, put a file with the message in the directory `messages-to-send/<friend_name>`, which will be automatically created. Messages to you will appear in `messages-received`.

To set up a connection with a friend:
1. Both of you should generate 40GB of fresh random numbers. Put them in a file called `<your-ID>.half-pad`.
```
dd if=/dev/urandom of=YOUR_ID.half-pad bs=1M count=40000
```
2. Both of you should write the current UTC date in a second file.
```
date -u "+%Y-%m-%d" >THEIR_ID.start-date.txt
```

The file is be short and looks like this:
```
2021-05-13
```

3. Exchange `.half-pad` files, so you each have both half-pad. For security, you shouldn't use the internet for this step. In increasing order of paranoia, use LAN, USB, or CD/DVD.
4. Xor the bin files together, and delete the originals. The final file should be called `<their-ID>.pad`.

```
xor --same-size YOUR_ID.half-pad THEIR_ID.half-pad >THEIR_ID.pad && shred -zu YOUR_ID.half-pad THEIR_ID.half-pad
```
5. Put the `.pad` and `.txt` files in the 'pads' directory of ok-mixnet.
