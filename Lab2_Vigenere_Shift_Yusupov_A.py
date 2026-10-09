import collections
import string


# ==============================================================================
# PART 1: SHIFT CIPHER DECRYPTION VIA FREQUENCY CROSS-CORRELATION
# ==============================================================================

# Standard letter frequencies for English (A-Z)
eng_freq = [
    0.082,
    0.015,
    0.028,
    0.043,
    0.127,
    0.022,
    0.020,
    0.061,
    0.070,
    0.002,
    0.008,
    0.040,
    0.024,
    0.067,
    0.075,
    0.019,
    0.001,
    0.060,
    0.063,
    0.091,
    0.028,
    0.010,
    0.023,
    0.001,
    0.020,
    0.001,
]

shift_ciphertext = (
    'Dolu fvb dlyl h ahkwvsl huk P dhz h mpzo Pu aol Whslvgvpj aptl, Huk '
    'zpkl if zpkl vu aol liipun apkl Dl zwyhdslk aoyvbno aol vvgl huk zsptl, '
    'Vy zrpaalylk dpao thuf h jhbkhs mspw aoyvbno aol klwaoz vm Jhtiyphu mlu '
    'Tf olhya dhz ypml dpao aol qvf vm spml, Mvy P svclk fvb lclu aolu.'
)


def decrypt_shift_cipher(text, eng_freq):
    # Step 1: Extract only alphabetic characters and convert to lower case to calculate frequencies
    clean_text = [c.lower() for c in text if c.isalpha()]
    total_chars = len(clean_text)

    # Step 2: Count frequencies of each letter in the ciphertext
    counts = collections.Counter(clean_text)

    # Step 3: Compute normalized frequency distribution vector for ciphertext (A-Z)
    obs_freq = [
        counts[chr(ord('a') + i)] / total_chars for i in range(26)
    ]

    best_shift = 0
    max_correlation = -1.0

    # Step 4: Test all possible 26 shifts and calculate cross-correlation with English frequencies
    for s in range(26):
        # Shift the observed frequency vector by s steps
        shifted_obs = [obs_freq[(i + s) % 26] for i in range(26)]

        # Calculate scalar product (cross-correlation) between shifted distribution and standard English frequencies
        correlation = sum(
            shifted_obs[i] * eng_freq[i] for i in range(26)
        )

        # Track the shift value that produces the maximum correlation
        if correlation > max_correlation:
            max_correlation = correlation
            best_shift = s

    # Step 5: Decrypt the original ciphertext preserving original casing and punctuation
    decrypted_chars = []
    for c in text:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            # Shift backwards by best_shift
            decrypted_char = chr((ord(c) - base - best_shift) % 26 + base)
            decrypted_chars.append(decrypted_char)
        else:
            decrypted_chars.append(c)

    return best_shift, ''.join(decrypted_chars)


# Execute Shift Cipher Decryption
shift_key, shift_plaintext = decrypt_shift_cipher(
    shift_ciphertext, eng_freq
)
print(f'=== SHIFT CIPHER RESULTS ===')
print(f'Detected Shift Key: {shift_key}')
print(f'Decrypted Text:\n{shift_plaintext}\n')


# ==============================================================================
# PART 2: VIGENÈRE CIPHER DECRYPTION VIA INDEX OF COINCIDENCE (IC)
# ==============================================================================

vigenere_ciphertext = (
    'opkjcpcsrqtkhespzxxsjmuinieiovvryaaqaeicjnystxnemmbyzrvvvjopwxzinqjibxzjdmjfsxnizvjiqidfzzymlxyeiljiqidfzzzaspwxcbnihe'
    'spzxxsjmuinbnijiehjzutsvrxdvmwmwkihaujharvzvgqsgfqhwtroqvsabnijycrzzgfwpzxtxuxsrkmvtxmgorxopkxwqvsaxafzmteoquroruxcmic'
    'piirjbkwwwjyzqtavmtlopkzipeimihmzmkcvxviovvhnwlxkeiiqmxwwsewvzkmriexdnoirmwoiwcrhlzwdvlsfqrxdwtmgtiinmtxshfrgggwowlqhi'
    'xcqsdtgmzirikedtyefirzvqreppvjmwsxvijspziiwrumxizirmexcmkrrrfxzxriowvrjbkxvekiqmtmtxyihmzlchfjvbzeqoyenvuxpivrpbopwdvh'
    'jzgrsbgpjqzwqvztoqyrcxtymzkrhppadlkpmemedtgfzifropkmbxvvimzedskiiboezzlpimxepmcmognegfviiqjibxzjdmjydhrxzazswxvqnivtse'
    'imioordvvzdwawwwjyzaujqcsimvuxswrvztowhiumijuprrvadvlsfqrxdwtgcrkedvkhwrklzcvhoxvadtredtvemqtmhecmxqfirgfpjzkhhioxrpkv'
    'segtgqieppvxcmzeppvpdazwogmiicsfsvzrmmjavmtlxwxvswgsilyxcxyixwsqcrmygvkvofzpdboigeehzfvsgyiinkbizmjxvkuqdmceoqurcjjxvv'
    'jefhzdzlteaijjjzbyzrvvvjopwxzinithcxyimqtjcvdeoqurgitymqzcsbgsncxig'
)


def calculate_ic(text):
    """Calculates the Index of Coincidence for a given string."""
    N = len(text)
    if N <= 1:
        return 0
    counts = collections.Counter(text)
    return sum(n * (n - 1) for n in counts.values()) / (N * (N - 1))


def find_key_length(ciphertext, max_len=20):
    """Finds most probable key length by measuring average IC across key slices."""
    best_len = 1
    closest_ic_diff = 1.0

    for klen in range(1, max_len + 1):
        # Step 1: Divide ciphertext into klen columns
        slices = [ciphertext[i::klen] for i in range(klen)]
        # Step 2: Compute average IC across all slices
        avg_ic = sum(calculate_ic(s) for s in slices) / klen

        # Target IC for natural English text is ~0.067
        ic_diff = abs(avg_ic - 0.067)
        if ic_diff < closest_ic_diff:
            closest_ic_diff = ic_diff
            best_len = klen

    return best_len


def recover_vigenere_key(ciphertext, key_len, eng_freq):
    """Recovers each letter of the Vigenere key using frequency cross-correlation on each slice."""
    key = []

    for i in range(key_len):
        # Step 1: Take all characters encrypted by key position i
        slice_text = ciphertext[i::key_len]
        total_chars = len(slice_text)
        counts = collections.Counter(slice_text)

        # Step 2: Observed frequency array for this slice
        obs_freq = [
            counts[chr(ord('a') + j)] / total_chars for j in range(26)
        ]

        best_shift = 0
        max_corr = -1.0

        # Step 3: Test shifts 0..25 against English distribution
        for shift in range(26):
            corr = sum(
                obs_freq[(j + shift) % 26] * eng_freq[j] for j in range(26)
            )
            if corr > max_corr:
                max_corr = corr
                best_shift = shift

        # Step 4: Map optimal shift to key letter ('a' + shift)
        key.append(chr(ord('a') + best_shift))

    return ''.join(key)


def decrypt_vigenere(ciphertext, key):
    """Decrypts Vigenere ciphertext given the recovered keyword."""
    plaintext = []
    key_len = len(key)

    for i, char in enumerate(ciphertext):
        # Shift back by value corresponding to key character
        shift = ord(key[i % key_len]) - ord('a')
        plain_char = chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
        plaintext.append(plain_char)

    return ''.join(plaintext)


# Execute Vigenère Decryption
vigenere_clean = ''.join(c.lower() for c in vigenere_ciphertext if c.isalpha())
key_length = find_key_length(vigenere_clean)
recovered_key = recover_vigenere_key(vigenere_clean, key_length, eng_freq)
vigenere_plaintext = decrypt_vigenere(vigenere_clean, recovered_key)

print(f'=== VIGENÈRE CIPHER RESULTS ===')
print(f'Estimated Key Length: {key_length}')
print(f'Recovered Key: {recovered_key}')
print(f'Decrypted Text:\n{vigenere_plaintext}')