import pytest
from src.domain.services.authentication.user_registration_service import UserRegistrationService
from src.common.exceptions import PasswordPolicyError
from src.domain.value_objects.email import Email
from src.domain.value_objects.username import SecureUsername

SUPPORTED_LANGUAGES = ["en", "es", "fa", "ar"]

PASSWORD_CASES = [
    ("password_empty", "", "Password cannot be empty", {
        "es": "La contraseña no puede estar vacía",
        "fa": "رمز عبور نمی‌تواند خالی باشد",
        "ar": "لا يمكن أن تكون كلمة المرور فارغة"
    }),
    ("password_too_short", "Ab1!", "Password must be at least 8 characters long", {
        "es": "La contraseña debe tener al menos 8 caracteres",
        "fa": "رمز عبور باید حداقل 8 کاراکتر باشد",
        "ar": "يجب أن تكون كلمة المرور 8 حرفًا على الأقل"
    }),
    ("password_no_uppercase", "password123!", "Password must contain at least one uppercase letter", {
        "es": "La contraseña debe contener al menos una letra mayúscula",
        "fa": "رمز عبور باید حداقل یک حرف بزرگ داشته باشد",
        "ar": "يجب أن تحتوي كلمة المرور على حرف كبير واحد على الأقل"
    }),
    ("password_no_lowercase", "PASSWORD123!", "Password must contain at least one lowercase letter", {
        "es": "La contraseña debe contener al menos una letra minúscula",
        "fa": "رمز عبور باید حداقل یک حرف کوچک داشته باشد",
        "ar": "يجب أن تحتوي كلمة المرور على حرف صغير واحد على الأقل"
    }),
    ("password_no_digit", "Password!", "Password must contain at least one digit", {
        "es": "La contraseña debe contener al menos un dígito",
        "fa": "رمز عبور باید حداقل یک عدد داشته باشد",
        "ar": "يجب أن تحتوي كلمة المرور على رقم واحد على الأقل"
    }),
    ("password_no_special_char", "Password123", "Password must contain at least one special character", {
        "es": "La contraseña debe contener al menos un carácter especial",
        "fa": "رمز عبور باید حداقل یک کاراکتر ویژه داشته باشد",
        "ar": "يجب أن تحتوي كلمة المرور على حرف خاص واحد على الأقل"
    }),
]

@pytest.mark.asyncio
@pytest.mark.parametrize("lang", SUPPORTED_LANGUAGES)
@pytest.mark.parametrize("case_key,password,expected_en,translations", PASSWORD_CASES)
async def test_password_policy_i18n(service, mock_user_repository, lang, case_key, password, expected_en, translations):
    """Test password policy errors are correctly translated for each supported language."""
    username = SecureUsername("testuser")
    email = Email("test@example.com")
    mock_user_repository.get_by_username.return_value = None
    mock_user_repository.get_by_email.return_value = None
    
    expected_message = translations.get(lang, expected_en)
    
    with pytest.raises(PasswordPolicyError) as exc_info:
        await service.register_user(
            username=username,
            email=email,
            password=password,
            language=lang
        )
    assert expected_message in str(exc_info.value) 