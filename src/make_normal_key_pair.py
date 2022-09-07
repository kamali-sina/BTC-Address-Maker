import key_maker as key_maker

if __name__ == '__main__':
    private_key = key_maker.get_private_key()
    wif = key_maker.get_wif_key(private_key)
    compressed_key = key_maker.get_compressed_public_key(private_key)
    wallet_address = key_maker.get_wallet_address(compressed_key)
    print(f'wif: {wif}\npub: {wallet_address}')