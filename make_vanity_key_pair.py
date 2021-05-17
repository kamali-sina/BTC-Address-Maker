import key_maker
import sys
import itertools
import threading
import time
import sys

'''
wif: cV8wuxebvFnxCw7NC17Fch69bzGHDy8T9A6NyABdhpLywdmd4omF
pub: msinxQbFhdWpurthWmXiggzJNbNtH3aJud
'''

done = False
def animate():
    for c in itertools.cycle(['|', '/', '-', '\\']):
        if done:
            break
        sys.stdout.write('\rloading ' + c)
        sys.stdout.flush()
        time.sleep(0.1)
    sys.stdout.write('\rDone!     ')

if __name__ == '__main__':
    if (len(sys.argv) < 2):
        print('Usage: python make_vanity_key_pair <vanity_chars>')
        exit(1)
    print(f'searching for <{sys.argv[1]}>...')
    target = sys.argv[1]
    target_len = len(target)
    i = 0
    c = 0
    while(1):
        if (i > 10000):
            i = 0
            c += 1
            print(f'searched {c}0000 private keys...')
        private_key = key_maker.get_private_key()
        compressed_key = key_maker.get_compressed_public_key(private_key)
        wallet_address = key_maker.get_wallet_address(compressed_key)
        if (wallet_address[1:1+target_len] == target):
            done = True
            time.sleep(1)
            print('found the target!')
            wif = key_maker.get_wif_key(private_key)
            print(f'wif: {wif}\npub: {wallet_address}')
            exit(1)
        i += 1
