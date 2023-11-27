import string 

# function for calculating index of coincidence
def calc_index_coincidence(text):
    text = text.upper().replace(" ", "") # probs not necessary given the ciphertext is already all uppercase with no spaces
    freq = [0] * 26 # stores frequency of each letter

    for char in text:
        if char.isalpha():
            freq[ord(char) - ord('A')] += 1 # iterates through alphabet, incrementing freq count for corresponding letters

    total_chars = sum(freq) # calculates total number of characters
    # using the standard formula for calculating IoC. (fi * (fi - 1)) / (N * (N - 1)), where fi = frequency of i-th letter in ciphertext 
    # & N = total number of chars in text.
    index_coincidence = sum([(f * (f - 1)) for f in freq]) / (total_chars * (total_chars - 1))
    return index_coincidence

# function for using index of coincidence to get potential keylength
def get_key_length(ciphertext, max_key_length):
    ciphertext = ciphertext.upper().replace(" ", "")
    # iterating through possible keylengths, dividing ciphertext into substrings based on key lengths in preparation of freq analysis
    for key_length in range(1, max_key_length + 1):
        substrings = [''] * key_length
        for i, char in enumerate(ciphertext):
            substrings[i % key_length] += char
        # for each key length calculating index of coincidence on corresponding substrings
        avg_ic = sum([calc_index_coincidence(substring) for substring in substrings]) / key_length
        print(f"Key Length: {key_length}, Average IC: {avg_ic:.4f}") # print results.

# function for decrypting with a given key
def decrypt(ciphertext, key):
    alphabet = list(string.ascii_uppercase) # initialise uppercase alphabet
    plaintext = '' # empty string for storing decrypted text
    key_idx = 0 # key index as a counter to keep track of current position

    # iterating thru ciphertext
    for cipher_char in ciphertext:
        if cipher_char.isalpha():
            c_idx = alphabet.index(cipher_char.upper()) # current index of character in ciphertext
            k_idx = alphabet.index(key[key_idx % len(key)].upper()) # index of current character in key
            p_idx = (c_idx - k_idx) % 26 # index of decrypted character in plaintext using vignere decryption formula (c - k) % mod 26
            p = alphabet[p_idx] # grabbing decrypted letter
            plaintext += p # appending to plaintext
            key_idx += 1 # incrementing key length for next iteration
        else:
            plaintext += cipher_char # append regardless of if its a letter or not
    return plaintext

# function for guessing random letters as a key, using frequency analysis
def guess_single_key_letter(substring):
    # uppercase alphabet
    alphabet = list(string.ascii_uppercase)
    freq = [0] * 26 # intialising to store frequency again

    for char in substring:
        if char.isalpha():
            freq[ord(char) - ord('A')] += 1 # increment the freq count for corresponding letters

    max_freq_idx = freq.index(max(freq)) # index of the max value of most occurring letter in substring
    key_letter = alphabet[(max_freq_idx - alphabet.index('E')) % 26] # calculating random letter based on e being most frequent letter of alphabet
    return key_letter

def guess_vigenere_key(ciphertext, max_key_length):
    # empty string for guessed key
    key = ''
    # iterating through different keylengths
    for key_length in range(1, max_key_length + 1):
        substrings = [''] * key_length # store substrings based on current key length
        for i, char in enumerate(ciphertext):
            substrings[i % key_length] += char # distribute characters from the ciphertext into substrings
        # combined the individually guessed letters from each substrings, into a key part and join the results
        key_part = ''.join([guess_single_key_letter(substring) for substring in substrings])
        key += key_part # append guessed key part to the key itself

    return key

def dictionary_attack(ciphertext, seven_letter_words):
    # grabbing words from seven_letter_words global array
    for word in seven_letter_words:
        potential_key = word.upper() # making sure dictionary word is uppercase, setting as own variable so doesnt get printed repetitively.

        # Repeat the potential key to match the entire length of the ciphertext, test if it works 
        key_repeated = (potential_key * (len(ciphertext) // len(potential_key))) + potential_key[:len(ciphertext) % len(potential_key)]

        # Decrypt the ciphertext using the current key
        decrypted_text = decrypt(ciphertext, key_repeated)

        print(f"Potential Key: {potential_key}\nDecrypted Text: {decrypted_text}\n")


ciphertext = 'VVVKLWAJQRRMPFQIEHESRQIXLZFTCIJXCLLKORROTSCPJIYEOPZPJCZMVVVHCTEUHRVPLSCBUXSPFCFESCEHQTTEAPYQFBTPYIPGLPLEHGURPLSHCGSIPYIPHISOFCGRKSELSOOEMLEHTCLKSLNVVISAZGGBZGXPAPGRROEHGFVAPCEPCJMRSTKBXWACIQFKSLWATUVTZAUNOKMZYEZDRRDTOPCTGFCRGRZRESEUTFPWZWKBXQLYYGGTEAPEUTISXNARHZZTEYKHZWNZMOCEMYXEVFFTZWIVOEECPAUGLGSLSCRVPLTDGDVVESAPRDIWMOWFEILYDCPLROLNVWESAPNJOSMELTUHYEEZFHSIEEWECGKWZXEUQRXEPRGRKVPPSHCIWSPLVSIMETSECDQZYIPOCPSLBKHRXDTNKHJVLYGGSOGPATHCIHPYSGTFVPDTUSJTPNICZCCESOUSNMESHKUYVLTNHOCPHSINSZXTDMQGKPJQOWBUMYTNNOEHLCECGKLPRANOYMDCARWUPJNONCEMDTNIQFEDEANFVKTZNUHYINSAPUVWMCOWUYXMJEWFFTPLNUSKXWPMGBKASTCJVRZPMEGBUMDLSVFFYDQOTARRJDPGQZIDSAXSSIPYHKUYPJMEPSWMNTANTFVESEIOCESMEEOLWPZFVVVGWPATWEKZQFQFVWEDIPTVVETLGOIILDAPRKLPARQJZWTZNQTJXZNKYOKICTNIDFMYESKBRVTOZQBVWQWAITCERLHTQYQWJKDBQPXOVDRJDDUBXNDCMIMXNTPWKFIELPHFUZHQZPKVNVZDFAZDLCDBGXXZCQGQPZNCIYWDMZLDMCNUTCYDEZBGOOZFRVEAVWKPBLUQMUTRJQGOKZNGRACQLCUWPLRTJSTPLDSKTZGLEIQBFJESEIOCESHAURZJQTCWZKMEHAUGVTLCAVSUMYEHGAFRZEYRWTKPYUUSFPZAHWGSYEEHGTLVESETFVPLEIQBJLTASYSIIYZTEZVECZBXWFYDXOTDYSWZGKQRPDTMKZRVTEIGGRVPDHCFVHMPTYSVRESEIOCESLNFHYIHSIVSTSNVAVCFWESAVAROPFPVVVKPYUUQRGLEUCOEHTYDGSUXSPGCZRLHLSKBZXTLLNMUIDNRKPVHLDCCQRXFLRQGVMNLPKZCEPLRNMURLDTWRZIDLLNWVHESEIOCESHIVVKLPNOEYRXTPLQFGPLNEFWKGWZSGHFWZXEEOTEEFAUDVGTPSQTTSXALGHVPJOIHTVVPYTCDGILCAPQVMYNOPGVUFPNESKLPLNESJXZCSQTKLPRANOYXSPCQQBEETENOEHXLJQFDMENHGZCWNZCMOKSZHETSKLZFGJHKSSLVGRZZPCGGRWVZXTJSDETYWJWKINZCMOKSZWIPSRXDZMGGKERPPTWFVEZTJOKKCZURGDETYRCRZEETOPHYMDHAUWEHPPDECIVPNTGLTIAEFQFKLPALCQVQPYTQTKLPNOEYRXTPLKUESCLNESFJESIUTRGESOYSMICWEFHFEEEEODKWEZRGGFPGPTJSVZZWUVWFRLCYJWJXZCYCBUTCPHKGKSCTCDWFKPZGTOGLJZFVVVGZNKCHFSDHHKQYYWEIOOKIWJPTCMIOQRWWKPPDSDSTEFDEVVVCHPRGPRWPOOPWEZLWIFOJWFXPVWFRDEOUHRVEHIVVZXQPLNHFXSPSVIUCZQBTCNREZFVHFGZXPCFVXSPPTSMMZFSNMRZLTLCPCIOLTCKZXSEHGWIQTEOEVFROCICZJVCYAUSHYPYCGFVWPLREVRROCEUCCZPEHGWJWFPTQRRCESEIOCESTSUSVRLWOPUNMESMCXFVXTTEVVPWDCQQBEEZOCGRRPLRNMUMGPRISEGPQRQAKLPHHKHVGZNKCHFSWTNGOXIHSIEVYEDYOVQFQAWEVSCCWZSVWKWLMINWKCEZPTCUYNPAPCMICLLNDZRVXALCIQTECJSCPDZRRWEOLYDIFVCRLLCVSSOJPNIDERPWJWCILWRGOUCMPIPUCMRSTKBTSWZUTOEHYZNUSOYLWLARZQZCPJWTXSPSKUEMQTCCBTIZQTJSJIEHOCBUSESETQYECLCVSIMDEIEGJLLCEFPPXSPCCQRXFTNCSYEOARGJZSFDLAPVIYPXRZRMYPDCKRCTYECFCMPCSVIUMPDBAGKVTNTCDGPTNAVWFRZQPCFJMXZNACEQTDIPHVVACEVSUHLEA'

max_key_length = 7  # You may adjust this based on the results
get_key_length(ciphertext, max_key_length)

guessed_key = guess_vigenere_key(ciphertext, max_key_length)
#print(f"Guessed Key: {guessed_key}")
#print("freq of letters in ciphertext : \n" + str(letter_freq))

plaintext = decrypt(ciphertext, guessed_key)
print("Decrypted Plaintext:")
print(plaintext)
seven_letter_words = [
    'ampulla', 'ancilla', 'armilla', 'barilla', 'canella', 'cavalla', 'cedilla',
    'codilla', 'coralla', 'corella', 'corolla', 'favella', 'gorilla', 'labella',
    'lamella', 'latilla', 'mamilla', 'manilla', 'maxilla', 'medulla', 'megilla',
    'micella', 'mycella', 'nigella', 'novella', 'padella', 'papilla', 'parella',
    'patella', 'perilla', 'rosella', 'rubella', 'sabella', 'sacella', 'sitella',
    'squilla', 'triella', 'vanilla', 'vexilla', 'zanella', 'zorilla'
]

# Call the function to guess the key
dictionary_attack(ciphertext, seven_letter_words)