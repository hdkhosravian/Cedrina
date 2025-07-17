# Email Services

Cedrina implements a comprehensive email service system with template rendering, multi-language support, and secure SMTP configuration. This system handles email confirmation, password reset notifications, and other transactional emails with enterprise-grade reliability.

## 🏗️ Architecture Overview

### **Core Components**
- **Email Service**: Domain service for email operations
- **Template Engine**: Jinja2-based template rendering with i18n support
- **SMTP Integration**: FastMail for secure email delivery
- **Multi-language Support**: Babel integration for internationalization
- **Security Features**: HTML escaping, secure SMTP configuration

### **Email Flow**
```
Email Request → Template Rendering → SMTP Delivery → Confirmation
      ↓              ↓                ↓              ↓
User Action → Jinja2 Engine → FastMail → Delivery Status
```

## 📧 Email Service Implementation

### **Core Email Service**
```python
class EmailService:
    """Domain service for handling email operations with security and i18n support."""
    
    def __init__(self, settings: EmailSettings):
        """Initialize EmailService with configuration."""
        self.settings = settings
        self._setup_jinja_environment()
        self._setup_fastmail()
    
    async def send_email(
        self,
        to_email: str,
        subject: str,
        html_content: str,
        text_content: Optional[str] = None
    ) -> bool:
        """Send email with HTML and optional text content."""
        
    def render_template(
        self, 
        template_name: str, 
        **context: Any
    ) -> str:
        """Render email template with provided context."""
```

### **Template Engine Setup**
```python
def _setup_jinja_environment(self) -> None:
    """Set up Jinja2 environment for template rendering."""
    template_dir = Path(self.settings.EMAIL_TEMPLATES_DIR)
    
    self.jinja_env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=True,  # Enable auto-escaping for security
        trim_blocks=True,
        lstrip_blocks=True
    )
    
    # Add custom filters for email formatting
    self.jinja_env.filters['format_datetime'] = self._format_datetime_filter
```

### **SMTP Configuration**
```python
def _setup_fastmail(self) -> None:
    """Set up FastMail for email delivery."""
    config = ConnectionConfig(
        MAIL_USERNAME=self.settings.SMTP_USERNAME,
        MAIL_PASSWORD=self.settings.SMTP_PASSWORD.get_secret_value(),
        MAIL_FROM=self.settings.FROM_EMAIL,
        MAIL_PORT=self.settings.SMTP_PORT,
        MAIL_SERVER=self.settings.SMTP_HOST,
        MAIL_FROM_NAME=self.settings.FROM_NAME,
        MAIL_STARTTLS=self.settings.SMTP_USE_TLS,
        MAIL_SSL_TLS=self.settings.SMTP_USE_SSL,
        USE_CREDENTIALS=bool(self.settings.SMTP_USERNAME and self.settings.SMTP_PASSWORD),
        VALIDATE_CERTS=True,  # Always validate certificates for security
    )
    
    self.fastmail = FastMail(config)
```

## 📝 Email Templates

### **Template Structure**
```
templates/email/
├── email_confirmation_en.html
├── email_confirmation_en.txt
├── email_confirmation_ar.html
├── email_confirmation_ar.txt
├── password_reset_en.html
├── password_reset_en.txt
└── ...
```

### **Template Example (HTML)**
```html
<!DOCTYPE html>
<html lang="{{ language }}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ subject }}</title>
</head>
<body>
    <div class="container">
        <h1>{{ greeting }}</h1>
        <p>{{ message }}</p>
        <a href="{{ confirmation_url }}" class="button">
            {{ confirm_button_text }}
        </a>
        <p>{{ footer_message }}</p>
    </div>
</body>
</html>
```

### **Template Example (Text)**
```text
{{ greeting }}

{{ message }}

{{ confirm_button_text }}: {{ confirmation_url }}

{{ footer_message }}
```

## 🌐 Multi-language Support

### **Language Detection**
```python
def get_email_language(user_language: str) -> str:
    """Get appropriate language for email templates."""
    supported_languages = ['en', 'ar', 'es', 'fa']
    
    if user_language in supported_languages:
        return user_language
    
    return 'en'  # Default to English
```

### **Template Selection**
```python
def get_template_name(base_name: str, language: str) -> str:
    """Get localized template name."""
    return f"{base_name}_{language}.html"
```

## 📧 Email Types

### **1. Email Confirmation**
- **Purpose**: Verify user email address during registration
- **Template**: `email_confirmation_{lang}.html/txt`
- **Content**: Confirmation link, user details, security notice

```python
async def send_confirmation_email(
    email_service: EmailService,
    user: User,
    confirmation_token: str,
    language: str
) -> bool:
    """Send email confirmation to user."""
    
    template_name = f"email_confirmation_{language}.html"
    text_template_name = f"email_confirmation_{language}.txt"
    
    context = {
        "user_name": user.username,
        "confirmation_url": f"{settings.BASE_URL}/api/v1/auth/confirm-email?token={confirmation_token}",
        "language": language
    }
    
    html_content = email_service.render_template(template_name, **context)
    text_content = email_service.render_template(text_template_name, **context)
    
    return await email_service.send_email(
        to_email=user.email,
        subject=get_translated_message("email_confirmation_subject", language),
        html_content=html_content,
        text_content=text_content
    )
```

### **2. Password Reset**
- **Purpose**: Allow users to reset forgotten passwords
- **Template**: `password_reset_{lang}.html/txt`
- **Content**: Reset link, security warnings, expiration notice

```python
async def send_password_reset_email(
    email_service: EmailService,
    user: User,
    reset_token: str,
    language: str
) -> bool:
    """Send password reset email to user."""
    
    template_name = f"password_reset_{language}.html"
    text_template_name = f"password_reset_{language}.txt"
    
    context = {
        "user_name": user.username,
        "reset_url": f"{settings.BASE_URL}/api/v1/auth/reset-password?token={reset_token}",
        "expiration_hours": 24,
        "language": language
    }
    
    html_content = email_service.render_template(template_name, **context)
    text_content = email_service.render_template(text_template_name, **context)
    
    return await email_service.send_email(
        to_email=user.email,
        subject=get_translated_message("password_reset_subject", language),
        html_content=html_content,
        text_content=text_content
    )
```

## 🔧 Configuration

### **Email Settings**
```python
# SMTP Configuration
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USERNAME = "noreply@cedrina.com"
SMTP_PASSWORD = "your_smtp_password"
SMTP_USE_TLS = True
SMTP_USE_SSL = False

# Email Settings
FROM_EMAIL = "noreply@cedrina.com"
FROM_NAME = "Cedrina Authentication"
EMAIL_TEMPLATES_DIR = "templates/email"

# Security Settings
EMAIL_HTML_ESCAPING = True
EMAIL_VALIDATE_CERTS = True
EMAIL_TIMEOUT_SECONDS = 30
```

### **Template Configuration**
```python
# Supported Languages
SUPPORTED_LANGUAGES = ["en", "ar", "es", "fa"]

# Template Settings
TEMPLATE_AUTOESCAPE = True
TEMPLATE_TRIM_BLOCKS = True
TEMPLATE_LSTRIP_BLOCKS = True

# Email Limits
MAX_EMAILS_PER_HOUR = 100
MAX_EMAILS_PER_USER_PER_DAY = 10
```

## 🎨 Usage Examples

### **Send Confirmation Email**
```python
# In registration service
async def register_user(self, username: str, email: str, password: str) -> User:
    """Register new user and send confirmation email."""
    
    # Create user
    user = await self.user_repository.create_user(username, email, password)
    
    # Generate confirmation token
    confirmation_token = await self.token_service.create_confirmation_token(user)
    
    # Send confirmation email
    language = get_user_language(request)
    await self.email_service.send_confirmation_email(
        user, confirmation_token, language
    )
    
    return user
```

### **Send Password Reset Email**
```python
# In password reset service
async def request_password_reset(self, email: str) -> bool:
    """Request password reset and send email."""
    
    # Find user by email
    user = await self.user_repository.find_by_email(email)
    if not user:
        return False
    
    # Generate reset token
    reset_token = await self.token_service.create_reset_token(user)
    
    # Send reset email
    language = get_user_language(request)
    await self.email_service.send_password_reset_email(
        user, reset_token, language
    )
    
    return True
```

## 🧪 Testing

### **Unit Tests**
```python
def test_email_template_rendering():
    """Test email template rendering."""
    
def test_email_service_send():
    """Test email sending functionality."""
    
def test_multi_language_support():
    """Test multi-language email support."""
    
def test_smtp_configuration():
    """Test SMTP configuration validation."""
```

### **Integration Tests**
```python
def test_confirmation_email_flow():
    """Test complete email confirmation flow."""
    
def test_password_reset_email_flow():
    """Test complete password reset email flow."""
    
def test_email_template_internationalization():
    """Test email template i18n functionality."""
```

## 📊 Monitoring

### **Email Metrics**
- **Email Volume**: Emails sent per time period
- **Delivery Rates**: Success/failure rates by type
- **Template Usage**: Most used templates and languages
- **Performance**: Email sending response times

### **Error Monitoring**
- **SMTP Errors**: SMTP connection and delivery errors
- **Template Errors**: Template rendering failures
- **Validation Errors**: Email address validation failures
- **Rate Limiting**: Email rate limiting events

## 🚀 Best Practices

### **Email Security**
- **HTML Escaping**: Always escape user content in templates
- **Secure SMTP**: Use TLS/SSL for email transmission
- **Certificate Validation**: Validate SMTP certificates
- **Rate Limiting**: Limit emails per user to prevent abuse

### **Template Design**
- **Responsive Design**: Mobile-friendly email templates
- **Accessibility**: Ensure templates are accessible
- **Branding**: Consistent branding across all emails
- **Testing**: Test templates across email clients

### **Performance Optimization**
- **Async Sending**: Use async email sending for performance
- **Template Caching**: Cache rendered templates
- **Connection Pooling**: Reuse SMTP connections
- **Error Handling**: Graceful handling of email failures

## 🔗 Related Documentation

- [Authentication System](../authentication/README.md) - User authentication flows
- [Token Management](../token-management/README.md) - JWT token security
- [Rate Limiting](../rate-limiting/README.md) - API rate limiting
- [Security Overview](../../security/overview.md) - Overall security architecture 