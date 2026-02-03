#!/usr/bin/env python3
"""
Password Strength Analyzer
A comprehensive tool for evaluating password security
Author: SkillCraft Technology
Version: 2.0
"""
import argparse
import math
import re
from typing import Dict, List, Tuple
from dataclasses import dataclass

# Expanded common password lists
COMMON_WORDS = {
    "password", "admin", "welcome", "qwerty", "iloveyou", "letmein",
    "login", "user", "test", "secret", "dragon", "football", "monkey",
    "master", "sunshine", "princess", "starwars", "computer", "trustno1",
    "freedom", "whatever", "batman", "michael", "shadow", "hello",
    "cookie", "summer", "superman", "killer", "access", "654321"
}

# Enhanced leetspeak mapping
LEET_MAP = str.maketrans({
    "@": "a", "4": "a", "^": "a",
    "8": "b", "|3": "b",
    "(": "c", "<": "c", "{": "c",
    "|)": "d", "|>": "d",
    "3": "e", "€": "e",
    "6": "g", "9": "g",
    "#": "h", "|-|": "h",
    "!": "i", "1": "i", "|": "i",
    "7": "t", "+": "t",
    "0": "o",
    "$": "s", "5": "s",
    "|_": "l",
    "2": "z",
})

# Keyboard patterns
KEYBOARD_SEQUENCES = [
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "qazwsxedc", "plokijuhygvcftrdxeszwaq",
    "1234567890", "!@#$%^&*()",
]

ALPHABET_SEQUENCES = [
    "abcdefghijklmnopqrstuvwxyz",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
]


@dataclass
class PasswordMetrics:
    """Comprehensive password metrics"""
    length: int
    has_lower: bool
    has_upper: bool
    has_digit: bool
    has_symbol: bool
    unique_chars: int
    entropy_bits: float
    charset_size: int


def analyze_character_composition(password: str) -> PasswordMetrics:
    """Analyze the character composition of the password"""
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)
    
    # Calculate character pool size
    charset_size = 0
    if has_lower: charset_size += 26
    if has_upper: charset_size += 26
    if has_digit: charset_size += 10
    if has_symbol: charset_size += 33
    charset_size = max(charset_size, 1)
    
    # Calculate theoretical entropy
    entropy_bits = len(password) * math.log2(charset_size)
    
    return PasswordMetrics(
        length=len(password),
        has_lower=has_lower,
        has_upper=has_upper,
        has_digit=has_digit,
        has_symbol=has_symbol,
        unique_chars=len(set(password)),
        entropy_bits=entropy_bits,
        charset_size=charset_size
    )


def detect_patterns(password: str) -> Dict[str, int]:
    """Detect various patterns that weaken passwords"""
    patterns = {
        "sequential": 0,
        "repeated_chars": 0,
        "repeated_patterns": 0,
        "keyboard_patterns": 0,
        "common_substitutions": 0,
    }
    
    lower_pass = password.lower()
    
    # Check for alphabet/number sequences (3+ chars)
    for sequence in ALPHABET_SEQUENCES + ["0123456789"]:
        for i in range(len(sequence) - 2):
            chunk = sequence[i:i+3]
            if chunk in lower_pass or chunk[::-1] in lower_pass:
                patterns["sequential"] += 1
    
    # Check for keyboard patterns
    for kbd_seq in KEYBOARD_SEQUENCES:
        for i in range(len(kbd_seq) - 2):
            chunk = kbd_seq[i:i+3]
            if chunk in lower_pass or chunk[::-1] in lower_pass:
                patterns["keyboard_patterns"] += 1
    
    # Repeated characters (aaa, 111, etc.)
    if re.search(r"(.)\1{2,}", password):
        patterns["repeated_chars"] = len(re.findall(r"(.)\1{2,}", password))
    
    # Repeated patterns (abab, 123123, etc.)
    for pattern_len in [2, 3, 4]:
        pattern = f"(.{{{pattern_len}}})" + f"\\1{{{1},}}"
        if re.search(pattern, password):
            patterns["repeated_patterns"] += 1
    
    # Common substitutions (p@ssw0rd style)
    common_subs = ["@", "0", "1", "3", "$", "!"]
    patterns["common_substitutions"] = sum(1 for c in password if c in common_subs)
    
    return patterns


def check_dictionary(password: str) -> Tuple[int, List[str]]:
    """Check against common words with leetspeak normalization"""
    matches = []
    plain = password.lower()
    
    # Simple leetspeak normalization
    normalized = plain
    for leet, normal in LEET_MAP.items():
        normalized = normalized.replace(leet, normal)
    
    for word in COMMON_WORDS:
        if word in plain or word in normalized:
            matches.append(word)
    
    # Check for year patterns (1990-2030)
    years = re.findall(r"(19\d{2}|20[0-3]\d)", password)
    if years:
        matches.extend([f"year:{y}" for y in years])
    
    # Check for common number patterns
    if re.search(r"123|234|456|789|000|111|999", password):
        matches.append("common_numbers")
    
    return len(matches), matches


def calculate_crack_time(entropy_bits: float) -> Dict[str, str]:
    """
    Estimate time to crack password under different scenarios
    """
    def format_time(seconds: float) -> str:
        if seconds < 1:
            return "< 1 second"
        
        intervals = [
            ("century", 3155760000),
            ("year", 31557600),
            ("month", 2629800),
            ("week", 604800),
            ("day", 86400),
            ("hour", 3600),
            ("minute", 60),
            ("second", 1),
        ]
        
        for name, seconds_in_unit in intervals:
            if seconds >= seconds_in_unit:
                value = seconds / seconds_in_unit
                plural = "s" if value >= 2 else ""
                return f"{value:.1f} {name}{plural}"
        
        return f"{seconds:.2f} seconds"
    
    # Different attack scenarios
    scenarios = {
        "offline_fast": 1e12,      # GPU cluster (1 trillion/sec)
        "offline_slow": 1e9,       # Standard GPU (1 billion/sec)
        "online_throttled": 1e3,   # Online with rate limiting (1000/sec)
        "online_strict": 1e1,      # Strict online (10/sec)
    }
    
    # Average attempts = 2^(bits-1)
    average_attempts = 2 ** max(entropy_bits - 1, 0)
    
    estimates = {}
    for scenario, rate in scenarios.items():
        seconds = average_attempts / rate
        estimates[scenario] = format_time(seconds)
    
    return estimates


def score_password(password: str) -> Dict:
    """
    Comprehensive password scoring algorithm
    Returns score (0-100), label, and detailed feedback
    """
    if not password:
        return {
            "score": 0,
            "label": "Empty",
            "strength_level": 0,
            "entropy_bits": 0.0,
            "feedback": ["Password cannot be empty"],
            "crack_time": calculate_crack_time(0),
            "details": {}
        }
    
    # Analyze password
    metrics = analyze_character_composition(password)
    patterns = detect_patterns(password)
    dict_hits, dict_words = check_dictionary(password)
    
    # Initialize score
    score = 0
    feedback = []
    
    # 1. Length scoring (0-35 points)
    length = metrics.length
    if length < 6:
        score += 0
        feedback.append("❌ Use at least 8 characters (12+ recommended)")
    elif length < 8:
        score += 10
        feedback.append("⚠️  Use at least 12 characters for better security")
    elif length < 12:
        score += 20
    elif length < 16:
        score += 30
    else:
        score += 35
    
    # 2. Character variety (0-30 points)
    variety_count = sum([
        metrics.has_lower,
        metrics.has_upper,
        metrics.has_digit,
        metrics.has_symbol
    ])
    variety_scores = [0, 8, 16, 24, 30]
    score += variety_scores[variety_count]
    
    if not metrics.has_lower:
        feedback.append("➕ Add lowercase letters")
    if not metrics.has_upper:
        feedback.append("➕ Add uppercase letters")
    if not metrics.has_digit:
        feedback.append("➕ Add numbers")
    if not metrics.has_symbol:
        feedback.append("➕ Add special characters (!@#$%^&*)")
    
    # 3. Entropy bonus (0-20 points)
    entropy_bonus = min(int(metrics.entropy_bits / 5), 20)
    score += entropy_bonus
    
    # 4. Uniqueness bonus (0-15 points)
    uniqueness_ratio = metrics.unique_chars / length if length > 0 else 0
    if uniqueness_ratio > 0.8:
        score += 15
    elif uniqueness_ratio > 0.6:
        score += 10
    elif uniqueness_ratio > 0.4:
        score += 5
    else:
        feedback.append("⚠️  Too many repeated characters")
    
    # 5. Apply penalties
    total_penalty = 0
    
    # Pattern penalties
    if patterns["sequential"] > 0:
        penalty = min(patterns["sequential"] * 8, 25)
        total_penalty += penalty
        feedback.append("❌ Avoid sequences (abc, 123, xyz)")
    
    if patterns["keyboard_patterns"] > 0:
        penalty = min(patterns["keyboard_patterns"] * 10, 30)
        total_penalty += penalty
        feedback.append("❌ Avoid keyboard patterns (qwerty, asdf)")
    
    if patterns["repeated_chars"] > 0:
        penalty = min(patterns["repeated_chars"] * 10, 25)
        total_penalty += penalty
        feedback.append("❌ Avoid repeated characters (aaa, 111)")
    
    if patterns["repeated_patterns"] > 0:
        penalty = min(patterns["repeated_patterns"] * 8, 20)
        total_penalty += penalty
        feedback.append("❌ Avoid repeated patterns (abcabc)")
    
    # Dictionary penalties
    if dict_hits > 0:
        penalty = min(dict_hits * 15, 40)
        total_penalty += penalty
        if any("year:" in w for w in dict_words):
            feedback.append("❌ Avoid using years")
        if len([w for w in dict_words if "year:" not in w and w != "common_numbers"]) > 0:
            feedback.append("❌ Avoid common words (even with l33tspeak)")
        if "common_numbers" in dict_words:
            feedback.append("❌ Avoid common number sequences")
    
    # Final score calculation
    score = max(0, min(100, score - total_penalty))
    
    # Determine strength label
    if score < 20:
        label = "Very Weak"
        strength_level = 1
        color = "#ef4444"
    elif score < 40:
        label = "Weak"
        strength_level = 2
        color = "#f97316"
    elif score < 60:
        label = "Moderate"
        strength_level = 3
        color = "#eab308"
    elif score < 80:
        label = "Strong"
        strength_level = 4
        color = "#22c55e"
    else:
        label = "Excellent"
        strength_level = 5
        color = "#10b981"
    
    # Add positive feedback for strong passwords
    if score >= 80 and not feedback:
        feedback.append("✅ Excellent password strength!")
    elif score >= 60 and len(feedback) <= 1:
        feedback.append("✅ Good password strength")
    
    return {
        "score": score,
        "label": label,
        "strength_level": strength_level,
        "color": color,
        "entropy_bits": round(metrics.entropy_bits, 2),
        "feedback": feedback,
        "crack_time": calculate_crack_time(metrics.entropy_bits),
        "details": {
            "length": length,
            "unique_chars": metrics.unique_chars,
            "charset_size": metrics.charset_size,
            "patterns_found": sum(patterns.values()),
            "dictionary_hits": dict_hits,
            "patterns": patterns,
            "dictionary_matches": dict_words if dict_words else None,
        }
    }


def main():
    """CLI interface for password strength assessment"""
    parser = argparse.ArgumentParser(
        description="Password Strength Analyzer - SkillCraft Technology",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python password_analyzer.py -p "Password123"
  python password_analyzer.py -p "Tr0ub4dor&3"
  python password_analyzer.py -p "correct-horse-battery-staple"
        """
    )
    parser.add_argument(
        "--password", "-p",
        help="Password to evaluate",
        required=False
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show detailed analysis"
    )
    
    args = parser.parse_args()
    
    if not args.password:
        print("Password Strength Analyzer")
        print("=" * 50)
        print("\nUsage: python password_analyzer.py -p \"YourPassword\"")
        print("\nTry these examples:")
        print("  python password_analyzer.py -p \"password123\"")
        print("  python password_analyzer.py -p \"C0rrect-H0rse-Battery-Staple!\"")
        return
    
    result = score_password(args.password)
    
    print("\n" + "=" * 60)
    print(f"PASSWORD STRENGTH ANALYSIS")
    print("=" * 60)
    print(f"\n{'Score:':<20} {result['score']}/100")
    print(f"{'Strength Level:':<20} {result['label']}")
    print(f"{'Entropy:':<20} {result['entropy_bits']} bits")
    print(f"{'Character Pool:':<20} {result['details']['charset_size']} characters")
    
    print(f"\n{'CRACK TIME ESTIMATES':^60}")
    print("-" * 60)
    for scenario, time in result['crack_time'].items():
        scenario_name = scenario.replace("_", " ").title()
        print(f"  {scenario_name:<25} {time}")
    
    if result['feedback']:
        print(f"\n{'RECOMMENDATIONS':^60}")
        print("-" * 60)
        for tip in result['feedback']:
            print(f"  {tip}")
    
    if args.verbose and result['details']['patterns_found'] > 0:
        print(f"\n{'PATTERNS DETECTED':^60}")
        print("-" * 60)
        for pattern_type, count in result['details']['patterns'].items():
            if count > 0:
                pattern_name = pattern_type.replace("_", " ").title()
                print(f"  {pattern_name}: {count}")
    
    print("\n" + "=" * 60 + "\n")


if __name__ == "__main__":
    main()
