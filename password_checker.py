"""
password_checker.py
Enhanced password analysis with proper HIBP API integration.
"""

import math
import re
import os
import hashlib
import requests
from collections import Counter
from typing import Dict, List, Tuple, Set, Optional

# --------------------------- #
# Utilities: entropy / classes
# --------------------------- #

def shannon_entropy(password: str) -> float:
    """Calculate Shannon entropy in bits for the password."""
    if not password:
        return 0.0

    length = len(password)
    frequencies = Counter(password)

    entropy = 0.0
    for count in frequencies.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy * length

def char_classes(password: str) -> Dict[str, bool]:
    """Detect which character classes are present."""
    return {
        'lower': bool(re.search(r'[a-z]', password)),
        'upper': bool(re.search(r'[A-Z]', password)),
        'digit': bool(re.search(r'\d', password)),
        'symbol': bool(re.search(r'[^A-Za-z0-9]', password))
    }

# --------------------------- #
# Dictionary / pattern checks
# --------------------------- #

def load_wordlist(path: str, min_word_len: int = 3) -> Set[str]:
    """Load dictionary file and return set of lowercase words."""
    words = set()

    if not os.path.exists(path):
        print(f"Warning: Wordlist file not found at {path}")
        return words

    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as file:
            for line in file:
                word = line.strip()
                if len(word) >= min_word_len:
                    words.add(word.lower())
        print(f"Loaded {len(words)} words from wordlist")
    except (IOError, UnicodeError) as e:
        print(f"Error loading wordlist: {e}")

    return words

def dictionary_matches(password: str, wordlist: Set[str]) -> List[str]:
    """Find dictionary words as substrings in password."""
    matches = []

    if not wordlist:
        return matches

    lower_password = password.lower()

    # Check for exact matches first
    if lower_password in wordlist:
        matches.append(lower_password)

    # Check for substrings (longer words first for better matching)
    sorted_words = sorted(wordlist, key=len, reverse=True)
    for word in sorted_words:
        if word in lower_password and word not in matches:
            matches.append(word)

    return matches[:10]  # Limit to 10 matches

def detect_common_patterns(password: str) -> Tuple[bool, Optional[str]]:
    """Check for common weak patterns in password."""
    lower_password = password.lower()

    # Common numeric sequences
    numeric_sequences = [
        '123', '1234', '12345', '123456', '1234567', '12345678', '123456789', '1234567890',
        '111', '1111', '11111', '111111', '1111111', '11111111', '111111111',
        '000', '0000', '00000', '000000', '0000000', '00000000', '000000000',
        '1212', '1122', '1313', '2000', '2001', '2020', '2021', '2022', '2023', '2024',
        '222', '2222', '22222', '222222',
        '333', '3333', '33333', '333333',
        '444', '4444', '44444', '444444',
        '555', '5555', '55555', '555555',
        '666', '6666', '66666', '666666',
        '777', '7777', '77777', '777777',
        '888', '8888', '88888', '888888',
        '999', '9999', '99999', '999999',
        '1010', '1212', '1313', '1414', '1515', '1616', '1717', '1818', '1919', '2020',
        '112233', '223344', '334455', '445566', '556677', '667788', '778899',
        '123123', '321321', '456456', '654654', '789789', '987987',
        '13579', '24680', '102030', '100200', '999888',
        '0101', '0202', '0303', '0404', '0505', '0606', '0707', '0808', '0909',
        '007', '008', '009', '010', '100', '110', '120', '130', '140', '150'
    ]

    # Common keyboard patterns
    keyboard_patterns = [
        'qwerty', 'qwertz', 'asdf', 'zxcv', 'qaz', 'wsx', 'edc', 'rfv', 'tgb', 'yhn', 'ujm',
        'qwe', 'asd', 'zxc', 'qwer', 'wert', 'erty', 'rtyu', 'tyui', 'yuio', 'uiop',
        'asdfg', 'sdfgh', 'dfghj', 'fghjk', 'ghjkl', 'zxcvb', 'xcvbn', 'cvbnm',
        '1qaz', '2wsx', '3edc', '4rfv', '5tgb', '6yhn', '7ujm', '8ik', '9ol', '0p',
        'qwertyuiop', 'asdfghjkl', 'zxcvbnm',
        '!qaz', '@wsx', '#edc', '$rfv', '%tgb', '^yhn', '&ujm', '*ik', '(ol', ')p',
        'qazwsx', 'wsxedc', 'edcrfv', 'rfvtgb', 'tfvgyb', 'yhnujm',
        'zaq', 'xsw', 'cde', 'vfr', 'bgt', 'nhy', 'mju', 'ki', 'lo', 'p',
        'pqowie', 'qopwer', 'sadjkl', 'fhgjk', 'ghfjdk', 'hjkl',
        'mnbvcx', 'lkjhgf', 'poiuyt', 'oiuyt', 'iuyt', 'uyt'
    ]

    # Common weak passwords
    common_passwords = [
        'password', 'admin', 'welcome', 'login', 'pass', 'passw', 'p@ssw0rd', 'p@ssword',
        'letmein', 'monkey', 'dragon', 'master', 'hello', 'freedom', 'whatever', 'qazwsx',
        'sunshine', 'princess', 'welcome', 'shadow', 'superman', 'baseball', 'football',
        'iloveyou', 'trustno1', 'access', 'solo', 'starwars', 'matrix', 'mustang',
        'pass123', 'password123', 'adminadmin', 'welcome123', 'login123',
        'letmein123', 'monkey123', 'dragon123', 'master123', 'hello123',

        # Top common passwords
        '123456', '123456789', '12345678', '12345', '1234567', '1234567890',
        'abc123', '000000', '111111', '123123', 'qwerty', 'password1',

        # Names and common words
        'michael', 'jordan', 'jennifer', 'michelle', 'jessica', 'robert', 'thomas',
        'daniel', 'george', 'andrew', 'charlie', 'david', 'richard', 'steven',
        'anthony', 'kevin', 'jason', 'matthew', 'gary', 'timothy', 'jose', 'larry',
        'jeffrey', 'frank', 'scott', 'eric', 'stephen', 'andrea', 'raymond', 'gregory',
        'joshua', 'jerry', 'dennis', 'walter', 'patrick', 'peter', 'harold', 'douglas',
        'henry', 'carl', 'arthur', 'ryan', 'roger', 'joe', 'juan', 'jack', 'albert',
        'jonathan', 'justin', 'terry', 'gerald', 'keith', 'samuel', 'willie', 'ralph',
        'lawrence', 'nicholas', 'roy', 'benjamin', 'bruce', 'brandon', 'adam', 'harry',
        'fred', 'wayne', 'billy', 'steve', 'louis', 'jeremy', 'aaron', 'randy',
        'howard', 'eugene', 'carlos', 'russell', 'bobby', 'victor', 'martin', 'ernest',
        'phillip', 'todd', 'jesse', 'craig', 'alan', 'shawn', 'clarence', 'sean',
        'philip', 'chris', 'johnny', 'earl', 'jimmy', 'antonio', 'danny', 'bryan',
        'tony', 'luis', 'mike', 'stanley', 'leonard', 'nathan', 'dale', 'manuel',
        'rodney', 'curtis', 'norman', 'allen', 'marvin', 'vincent', 'glenn', 'jeffery',
        'travis', 'jeff', 'chad', 'jacob', 'lee', 'melvin', 'alfred', 'kyle', 'francis',
        'bradley', 'jesus', 'herbert', 'frederick', 'ray', 'joel', 'edwin', 'don',
        'eddie', 'ricky', 'troy', 'randall', 'barry', 'alexander', 'bernard', 'mario',
        'leroy', 'francisco', 'marcus', 'micheal', 'theodore', 'clifford', 'miguel',
        'oscar', 'jay', 'jim', 'tom', 'calvin', 'alex', 'jon', 'ronnie', 'bill',
        'lloyd', 'tommy', 'leon', 'derek', 'warren', 'darrell', 'jerome', 'floyd',
        'leo', 'alvin', 'tim', 'wesley', 'gordon', 'dean', 'greg', 'jorge', 'dustin',
        'pedro', 'derrick', 'dan', 'lewis', 'zachary', 'corey', 'herman', 'maurice',
        'vernon', 'roberto', 'clyde', 'glen', 'hector', 'shane', 'ricardo', 'sam',
        'rick', 'lester', 'brent', 'ramon', 'charlie', 'tyler', 'gilbert', 'gene',

        # Sports and hobbies
        'baseball', 'football', 'soccer', 'basketball', 'hockey', 'tennis', 'golf',
        'cricket', 'rugby', 'swimming', 'running', 'cycling', 'boxing', 'wrestling',
        'fishing', 'hunting', 'camping', 'climbing', 'skiing', 'snowboard', 'surfing',
        'skateboard', 'gaming', 'chess', 'poker', 'blackjack', 'bingo', 'lottery',

        # Animals
        'tiger', 'lion', 'elephant', 'giraffe', 'zebra', 'monkey', 'dolphin', 'eagle',
        'hawk', 'falcon', 'wolf', 'fox', 'bear', 'panda', 'kangaroo', 'koala',
        'penguin', 'octopus', 'shark', 'whale', 'butterfly', 'dragonfly', 'spider',

        # Food and drinks
        'pizza', 'burger', 'pasta', 'sushi', 'steak', 'chicken', 'coffee', 'tea',
        'juice', 'water', 'beer', 'wine', 'whiskey', 'vodka', 'rum', 'champagne',

        # Colors
        'red', 'blue', 'green', 'yellow', 'orange', 'purple', 'pink', 'black',
        'white', 'gray', 'brown', 'silver', 'gold', 'cyan', 'magenta', 'maroon',

        # Cities and countries
        'london', 'paris', 'newyork', 'tokyo', 'berlin', 'rome', 'moscow', 'dubai',
        'sydney', 'toronto', 'chicago', 'losangeles', 'lasvegas', 'miami', 'boston',
        'seattle', 'houston', 'phoenix', 'philadelphia', 'sanfrancisco', 'denver',

        # Simple patterns
        'test', 'demo', 'sample', 'guest', 'user', 'default', 'temp', 'temporary',
        'backup', 'admin123', 'root', 'system', 'server', 'database', 'network',

        # Company and product names
        'google', 'microsoft', 'apple', 'amazon', 'facebook', 'twitter', 'instagram',
        'whatsapp', 'youtube', 'netflix', 'spotify', 'ubuntu', 'windows', 'linux',
        'android', 'iphone', 'samsung', 'nokia', 'sony', 'dell', 'hp', 'ibm',

        # Seasons and months
        'spring', 'summer', 'autumn', 'winter', 'january', 'february', 'march',
        'april', 'may', 'june', 'july', 'august', 'september', 'october', 'november',
        'december', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday',
        'saturday', 'sunday',

        # Romantic and emotional
        'love', 'lover', 'beloved', 'sweetheart', 'darling', 'honey', 'baby',
        'sweetie', 'angel', 'prince', 'princess', 'king', 'queen', 'forever',
        'always', 'together', 'happy', 'smile', 'dream', 'hope', 'faith', 'peace',
        'joy', 'fun', 'party', 'celebration', 'congratulations',

        # Technology terms
        'internet', 'website', 'webpage', 'online', 'offline', 'digital', 'virtual',
        'computer', 'laptop', 'desktop', 'tablet', 'smartphone', 'wireless',
        'bluetooth', 'wifi', 'ethernet', 'router', 'modem', 'server', 'client'
    ]

    # Check numeric sequences
    for seq in numeric_sequences:
        if seq in lower_password:
            return True, f"numeric sequence '{seq}'"

    # Check keyboard patterns
    for pattern in keyboard_patterns:
        if pattern in lower_password:
            return True, f"keyboard pattern '{pattern}'"

    # Check common passwords
    for common in common_passwords:
        if common in lower_password:
            return True, f"common password '{common}'"

    # Check repeated characters (aaaa)
    if len(password) > 0 and len(set(password)) == 1:
        return True, f"repeated '{password[0]}'"

    # Check repeated substrings (abcabc)
    if len(password) >= 4:
        for i in range(1, len(password) // 2 + 1):
            substring = password[:i]
            repeats = len(password) // len(substring)
            if password == substring * repeats:
                return True, f"repeated '{substring}'"

    # Check sequential patterns (abcd, 1234)
    sequential_patterns = [
        'abcdefghijklmnopqrstuvwxyz',
        'zyxwvutsrqponmlkjihgfedcba',
        'qwertyuiop',
        'asdfghjkl',
        'zxcvbnm'
    ]

    for seq in sequential_patterns:
        for i in range(len(seq) - 3):
            if seq[i:i+4] in lower_password:
                return True, 'sequential pattern'

    return False, None

# --------------------------- #
# Breach checks
# --------------------------- #

def check_hibp(password: str, user_agent: str = 'PasswordChecker/1.0') -> int:
    """
    Check password against HaveIBeenPwned API using k-anonymity.

    Args:
        password: Password to check
        user_agent: User agent string for API request

    Returns:
        Number of times password appears in breaches (0 if not found)
    """
    try:
        # Calculate SHA-1 hash
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1_hash[:5], sha1_hash[5:]

        # Make API request
        url = f'https://api.pwnedpasswords.com/range/{prefix}'
        headers = {
            'User-Agent': user_agent,
            'Add-Padding': 'true'  # Request padding for enhanced privacy
        }

        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code != 200:
            return 0

        # Parse response
        for line in response.text.splitlines():
            if ':' in line:
                hash_suffix, count = line.split(':', 1)
                if hash_suffix.strip() == suffix:
                    try:
                        return int(count.strip())
                    except ValueError:
                        return 1

    except requests.exceptions.RequestException:
        # Fail safely - treat as not breached
        return 0
    except Exception:
        return 0

    return 0

# --------------------------- #
# Scoring engine
# --------------------------- #

def score_password( password: str, wordlist: Optional[Set[str]] = None, do_hibp: bool = True ) -> Dict:
    """
    Comprehensive password strength analysis.

    Args:
        password: Password to analyze
        wordlist: Set of dictionary words for checking
        do_hibp: Whether to check against HIBP database

    Returns:
        Dictionary with detailed analysis and score
    """
    # Basic metrics
    length = len(password)
    entropy_bits = shannon_entropy(password)
    classes = char_classes(password)
    class_count = sum(classes.values())

    # Pattern and dictionary checks
    pattern_found, pattern = detect_common_patterns(password)
    dict_matches = dictionary_matches(password, wordlist) if wordlist else []

    # Breach checks
    hibp_count = check_hibp(password) if do_hibp else 0
    breach_count = hibp_count

    # Normalize metrics (0-1 scale)
    length_norm = min(length / 20.0, 1.0)           # 20+ chars = excellent
    entropy_norm = min(entropy_bits / 80.0, 1.0)    # 80+ bits = excellent
    class_norm = class_count / 4.0                  # 4 classes = 1.0
    pattern_score = 0.0 if pattern_found else 1.0
    dict_penalty = 1.0 if dict_matches else 0.0
    breach_norm = min(math.log10(breach_count + 1) / 6.0, 1.0) if breach_count > 0 else 0.0

    # Calculate base score (0-100)
    base_score = ( 0.30 * length_norm + 0.35 * entropy_norm + 0.20 * class_norm + 0.15 * pattern_score ) * 100

    # Apply penalties
    final_score = base_score
    final_score -= 25.0 * dict_penalty      # Dictionary penalty
    final_score -= 40.0 * breach_norm       # Breach penalty

    # Clamp score between 0-100
    final_score = max(0.0, min(100.0, round(final_score, 1)))

    # Determine verdict (5-level scale)
    if final_score > 80:
        verdict = 'Very Strong'
    elif final_score >= 60:
        verdict = 'Strong'
    elif final_score >= 40:
        verdict = 'Good'
    elif final_score >= 20:
        verdict = 'Weak'
    else:
        verdict = 'Very Weak'

    # Generate recommendations
    recommendations = []

    if length < 12:
        recommendations.append('Use at least 12 characters')
    elif length < 16:
        recommendations.append('Consider using 16+ characters for stronger security')

    if class_count < 3:
        recommendations.append('Mix character types (upper, lower, digits, symbols)')

    if entropy_bits < 40:
        recommendations.append('Use more random, unpredictable characters')

    if dict_matches:
        rec_text = 'Avoid dictionary words: ' + ', '.join(dict_matches[:3])
        recommendations.append(rec_text)

    if pattern_found:
        recommendations.append(f'Avoid common patterns: {pattern}')

    if breach_count > 0:
        recommendations.append(f'Password found in {breach_count:,} breaches - DO NOT USE')

    if not recommendations and final_score >= 80:
        recommendations.append('Good password! Consider using a password manager.')

    return {
        'score': final_score,
        'verdict': verdict,
        'length': length,
        'entropy_bits': round(entropy_bits, 2),
        'class_count': class_count,
        'classes': classes,
        'dict_matches': dict_matches,
        'pattern_found': pattern_found,
        'pattern': pattern,
        'hibp_count': hibp_count,
        'breach_count': breach_count,
        'components': {
            'length_norm': round(length_norm, 3),
            'entropy_norm': round(entropy_norm, 3),
            'class_norm': round(class_norm, 3),
            'pattern_score': round(pattern_score, 3),
            'breach_norm': round(breach_norm, 3)
        },
        'recommendations': recommendations
    }