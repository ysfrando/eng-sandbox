from typing import Optional
import chardet
from dataclasses import dataclass
from enum import Enum

class ValidationStatus(Enum):
    SUCCESS = "success"
    FAILURE = "failure"

@dataclass
class ValidationResult:
    status: ValidationStatus
    message: Optional[str] = None

class DocumentValidator:
    def __init__(self):
        self.MAX_SIZE = 10 * 1024 * 1024
        self.ALLOWED_TYPES = {'text/plain', 'text/markdown', 'application/msword'}

    def validate_document(self, document_content: bytes, content_type: str) -> ValidationResult:
        """
        Centralized validation routine for document processing
        All validation happens server-side for security
        """
        try:
            # Step 1: Detect and validate character encoding
            detected = chardet.detect(document_content)
            if detected['encoding'] not in ['utf-8', 'ascii']:
                return ValidationResult(
                    ValidationStatus.FAILURE, 
                    "Invalid character encoding. Please use UTF-8."
                    )
        
            # Step 2: Decode content to UTF-8 for consistent processing
            content = document_content.decode('UTF-8')

            # Step 3: Validate size
            if len(content) > self.MAX_SIZE:
                return ValidationResult(
                    ValidationStatus.FAILURE,
                    "Document exceeds maximum size limit"
                )

            # Step 4: Validate content type using allowlist
            if content_type not in self.ALLOWED_TYPES:
                return ValidationResult(
                    ValidationStatus.FAILURE,
                    f"Invalid Document type. Allowed types: {', '.join(self.ALLOWED_TYPES)}"
                )

            # Step 5: Additional security checks for potentially harmful content
            if self._contains_malicious_patterns(content):
                return ValidationResult(
                    ValidationStatus.FAILURE,
                    "Potentially harmful content detected"    
                )
                
            return ValidationResult(ValidationStatus.SUCCESS)

        except UnicodeDecodeError:
            return ValidationResult(
                ValidationStatus.FAILURE,
                "Invalid UTF-8 encoding"
            )
   
    def _contains_malicious_patterns(self, content: str) -> bool:
        """
        Check for potentially malicious patterns in the content
        This is a simplified example - in production, you'd have more comprehensive checks
        """
        dangerous_patterns = [
            '<script>',
            'javascript:',
            'data:text/html',
            'document.cookie'
        ]
        
        return any(pattern in content.lower() for pattern in dangerous_patterns)
