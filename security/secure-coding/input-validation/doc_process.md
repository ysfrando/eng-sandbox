**Server-side Validation:** The secure implementation moves all validation to the server side. Client-side validation can be easily bypassed using tools like browser dev tools or API clients, so it should never be the only validation layer.
**Centralized Validation:** The DocumentValidator class serves as a centralized validation routine, ensuring consistent validation across the application. This makes it easier to maintain, update, and audit security controls.
**Character Encoding:** The code first detects and validates the character encoding, then explicitly converts to UTF-8 before processing. This prevents character encoding attacks and ensures consistent processing.
Allowlist Approach: Instead of trying to block known bad inputs (denylisting), the code uses an allowlist of acceptable content types. This is more secure as it's impossible to predict all malicious inputs.
Multiple Validation Layers: The code implements several validation steps:

Character encoding validation
Size limits
Content type verification
Malicious pattern detection


Clear Error Handling: The code returns specific validation errors, helping legitimate users fix issues while not revealing sensitive information to potential attackers.
Strong Typing: The code uses Python's type hints and dataclasses to ensure type safety and make the code more maintainable.
